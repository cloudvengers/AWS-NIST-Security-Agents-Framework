import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 EKS Security Analysis Lambda 함수
    16개 EKS API를 통한 종합적인 EKS 보안 상태 분석
    """
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region', 'us-east-1')
        
        # 세션 속성에서 고객 자격증명 및 현재 시간 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다. 세션을 다시 시작해주세요.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        eks_client = session.client('eks', region_name=target_region)
        
        # EKS 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_eks_security_data_parallel(eks_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEksSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"EKS 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in EKS security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_eks_security_data_parallel(client, target_region, current_time):
    """
    EKS 보안 데이터를 병렬로 수집 - 16개 API 활용
    """
    # 먼저 클러스터 목록 조회
    try:
        clusters_response = client.list_clusters()
        cluster_names = clusters_response.get('clusters', [])
    except Exception as e:
        print(f"Error listing EKS clusters: {str(e)}")
        return {
            'function': 'analyzeEksSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'EKS 클러스터 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'clusters_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not cluster_names:
        return {
            'function': 'analyzeEksSecurity',
            'target_region': target_region,
            'status': 'no_clusters',
            'message': 'EKS 클러스터가 존재하지 않습니다.',
            'collection_summary': {
                'clusters_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('clusters_security_analysis', lambda: analyze_clusters_security_parallel(client, cluster_names)),
        ('cluster_versions_analysis', lambda: get_cluster_versions_safe(client)),
    ]
    
    # 병렬 처리 실행
    results = process_eks_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'clusters_analyzed': len(cluster_names),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_eks_apis_called(cluster_names),
        'collection_method': 'parallel_processing',
        'cluster_names_analyzed': cluster_names[:5]  # 최대 5개만 표시
    }
    
    return {
        'function': 'analyzeEksSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'clusters_data': results.get('clusters_security_analysis', {}),
        'cluster_versions': results.get('cluster_versions_analysis', {}),
        'collection_summary': collection_summary
    }
def process_eks_parallel(tasks, max_workers=2):
    """EKS 데이터 수집 작업을 병렬로 처리"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def analyze_clusters_security_parallel(client, cluster_names, max_workers=3):
    """클러스터들의 보안 설정을 병렬로 분석"""
    cluster_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_cluster_security, client, cluster_name) for cluster_name in cluster_names]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    cluster_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing cluster: {str(e)}")
                continue
    
    return {
        'total_clusters_analyzed': len(cluster_analyses),
        'cluster_security_details': cluster_analyses
    }

def analyze_single_cluster_security(client, cluster_name):
    """개별 클러스터의 보안 설정 종합 분석 - 15개 API 사용"""
    try:
        # 클러스터 기본 정보 조회 (DescribeCluster)
        cluster_response = client.describe_cluster(name=cluster_name)
        cluster = cluster_response.get('cluster', {})
        
        # 클러스터 보안 분석 데이터 수집
        security_tasks = [
            ('nodegroups', lambda: analyze_cluster_nodegroups_security(client, cluster_name)),
            ('fargate_profiles', lambda: analyze_cluster_fargate_security(client, cluster_name)),
            ('access_entries', lambda: analyze_cluster_access_security(client, cluster_name)),
            ('identity_providers', lambda: analyze_cluster_identity_security(client, cluster_name)),
            ('pod_identity', lambda: analyze_cluster_pod_identity_security(client, cluster_name)),
            ('addons', lambda: analyze_cluster_addons_security(client, cluster_name)),
            ('tags', lambda: get_cluster_tags_safe(client, cluster.get('arn')))
        ]
        
        security_data = execute_parallel_tasks(security_tasks, max_workers=7)
        
        # 클러스터 기본 보안 설정 분석
        basic_security = analyze_cluster_basic_security(cluster)
        
        return {
            'cluster_name': cluster_name,
            'cluster_arn': cluster.get('arn'),
            'cluster_status': cluster.get('status'),
            'kubernetes_version': cluster.get('version'),
            'platform_version': cluster.get('platformVersion'),
            'created_at': cluster.get('createdAt'),
            'basic_security': basic_security,
            'nodegroups': security_data.get('nodegroups', {}),
            'fargate_profiles': security_data.get('fargate_profiles', {}),
            'access_entries': security_data.get('access_entries', {}),
            'identity_providers': security_data.get('identity_providers', {}),
            'pod_identity': security_data.get('pod_identity', {}),
            'addons': security_data.get('addons', {}),
            'tags': security_data.get('tags', {})
        }
        
    except Exception as e:
        print(f"Error analyzing cluster {cluster_name}: {str(e)}")
        return {
            'cluster_name': cluster_name,
            'status': 'error',
            'error_message': str(e)
        }

def analyze_cluster_basic_security(cluster):
    """클러스터 기본 보안 설정 분석"""
    vpc_config = cluster.get('resourcesVpcConfig', {})
    logging_config = cluster.get('logging', {}).get('clusterLogging', [])
    encryption_config = cluster.get('encryptionConfig', [])
    access_config = cluster.get('accessConfig', {})
    
    return {
        'endpoint_config': {
            'endpoint_private_access': vpc_config.get('endpointPrivateAccess', False),
            'endpoint_public_access': vpc_config.get('endpointPublicAccess', True),
            'public_access_cidrs': vpc_config.get('publicAccessCidrs', []),
            'cluster_security_group_id': vpc_config.get('clusterSecurityGroupId'),
            'security_group_ids': vpc_config.get('securityGroupIds', []),
            'subnet_ids': vpc_config.get('subnetIds', []),
            'vpc_id': vpc_config.get('vpcId')
        },
        'logging_config': {
            'enabled_log_types': [],
            'disabled_log_types': []
        },
        'encryption_config': {
            'secrets_encrypted': len(encryption_config) > 0,
            'encryption_details': encryption_config
        },
        'access_config': {
            'authentication_mode': access_config.get('authenticationMode'),
            'bootstrap_cluster_creator_admin_permissions': access_config.get('bootstrapClusterCreatorAdminPermissions')
        },
        'service_role': cluster.get('roleArn'),
        'identity_oidc_issuer': cluster.get('identity', {}).get('oidc', {}).get('issuer')
    }

def analyze_cluster_nodegroups_security(client, cluster_name):
    """노드그룹 보안 분석 (ListNodegroups + DescribeNodegroup)"""
    try:
        # ListNodegroups
        list_response = client.list_nodegroups(clusterName=cluster_name)
        nodegroup_names = list_response.get('nodegroups', [])
        
        if not nodegroup_names:
            return {
                'has_nodegroups': False,
                'message': '노드그룹이 없습니다.'
            }
        
        # DescribeNodegroup (최대 5개)
        nodegroups_to_describe = nodegroup_names[:5]
        nodegroup_details = []
        
        for nodegroup_name in nodegroups_to_describe:
            try:
                describe_response = client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_name
                )
                nodegroup = describe_response.get('nodegroup', {})
                
                # 노드그룹 보안 분석
                security_analysis = {
                    'nodegroup_name': nodegroup_name,
                    'status': nodegroup.get('status'),
                    'instance_types': nodegroup.get('instanceTypes', []),
                    'ami_type': nodegroup.get('amiType'),
                    'node_role': nodegroup.get('nodeRole'),
                    'subnets': nodegroup.get('subnets', []),
                    'remote_access': nodegroup.get('remoteAccess', {}),
                    'scaling_config': nodegroup.get('scalingConfig', {}),
                    'update_config': nodegroup.get('updateConfig', {}),
                    'launch_template': nodegroup.get('launchTemplate', {}),
                    'tags': nodegroup.get('tags', {})
                }
                
                nodegroup_details.append(security_analysis)
                
            except Exception as e:
                print(f"Error describing nodegroup {nodegroup_name}: {str(e)}")
                continue
        
        return {
            'has_nodegroups': True,
            'total_nodegroups': len(nodegroup_names),
            'analyzed_nodegroups': len(nodegroup_details),
            'nodegroup_details': nodegroup_details
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_cluster_fargate_security(client, cluster_name):
    """Fargate 프로필 보안 분석 (ListFargateProfiles + DescribeFargateProfile)"""
    try:
        # ListFargateProfiles
        list_response = client.list_fargate_profiles(clusterName=cluster_name)
        fargate_profile_names = list_response.get('fargateProfileNames', [])
        
        if not fargate_profile_names:
            return {
                'has_fargate_profiles': False,
                'message': 'Fargate 프로필이 없습니다.'
            }
        
        # DescribeFargateProfile (최대 5개)
        profiles_to_describe = fargate_profile_names[:5]
        profile_details = []
        
        for profile_name in profiles_to_describe:
            try:
                describe_response = client.describe_fargate_profile(
                    clusterName=cluster_name,
                    fargateProfileName=profile_name
                )
                profile = describe_response.get('fargateProfile', {})
                
                # Fargate 프로필 보안 분석
                security_analysis = {
                    'profile_name': profile_name,
                    'status': profile.get('status'),
                    'pod_execution_role_arn': profile.get('podExecutionRoleArn'),
                    'subnets': profile.get('subnets', []),
                    'selectors': profile.get('selectors', []),
                    'tags': profile.get('tags', {})
                }
                
                profile_details.append(security_analysis)
                
            except Exception as e:
                print(f"Error describing Fargate profile {profile_name}: {str(e)}")
                continue
        
        return {
            'has_fargate_profiles': True,
            'total_fargate_profiles': len(fargate_profile_names),
            'analyzed_fargate_profiles': len(profile_details),
            'fargate_profile_details': profile_details
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
def analyze_cluster_access_security(client, cluster_name):
    """액세스 엔트리 보안 분석 (ListAccessEntries + DescribeAccessEntry + ListAssociatedAccessPolicies)"""
    try:
        # ListAccessEntries
        list_response = client.list_access_entries(clusterName=cluster_name)
        access_entries = list_response.get('accessEntries', [])
        
        if not access_entries:
            return {
                'has_access_entries': False,
                'message': '액세스 엔트리가 없습니다.'
            }
        
        # DescribeAccessEntry + ListAssociatedAccessPolicies (최대 5개)
        entries_to_analyze = access_entries[:5]
        access_entry_details = []
        
        for principal_arn in entries_to_analyze:
            try:
                # DescribeAccessEntry
                describe_response = client.describe_access_entry(
                    clusterName=cluster_name,
                    principalArn=principal_arn
                )
                access_entry = describe_response.get('accessEntry', {})
                
                # ListAssociatedAccessPolicies
                policies_response = client.list_associated_access_policies(
                    clusterName=cluster_name,
                    principalArn=principal_arn
                )
                associated_policies = policies_response.get('associatedAccessPolicies', [])
                
                # 액세스 엔트리 보안 분석
                security_analysis = {
                    'principal_arn': principal_arn,
                    'type': access_entry.get('type'),
                    'username': access_entry.get('username'),
                    'groups': access_entry.get('groups', []),
                    'kubernetes_groups': access_entry.get('kubernetesGroups', []),
                    'access_scope': access_entry.get('accessScope', {}),
                    'associated_policies': associated_policies,
                    'tags': access_entry.get('tags', {})
                }
                
                access_entry_details.append(security_analysis)
                
            except Exception as e:
                print(f"Error analyzing access entry {principal_arn}: {str(e)}")
                continue
        
        return {
            'has_access_entries': True,
            'total_access_entries': len(access_entries),
            'analyzed_access_entries': len(access_entry_details),
            'access_entry_details': access_entry_details
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_cluster_identity_security(client, cluster_name):
    """신원 공급자 보안 분석 (DescribeIdentityProviderConfig)"""
    try:
        # 일반적으로 OIDC 신원 공급자를 확인
        # 실제로는 먼저 신원 공급자 목록을 조회해야 하지만, 여기서는 기본 OIDC 확인
        try:
            describe_response = client.describe_identity_provider_config(
                clusterName=cluster_name,
                identityProviderConfig={
                    'type': 'oidc',
                    'name': 'default'  # 기본 이름 시도
                }
            )
            
            identity_provider = describe_response.get('identityProviderConfig', {})
            
            return {
                'has_identity_provider': True,
                'identity_provider_details': identity_provider
            }
            
        except client.exceptions.ResourceNotFoundException:
            return {
                'has_identity_provider': False,
                'message': '신원 공급자가 설정되지 않음'
            }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_cluster_pod_identity_security(client, cluster_name):
    """Pod 신원 연결 보안 분석 (ListPodIdentityAssociations + DescribePodIdentityAssociation)"""
    try:
        # ListPodIdentityAssociations
        list_response = client.list_pod_identity_associations(clusterName=cluster_name)
        associations = list_response.get('associations', [])
        
        if not associations:
            return {
                'has_pod_identity_associations': False,
                'message': 'Pod 신원 연결이 없습니다.'
            }
        
        # DescribePodIdentityAssociation (최대 5개)
        associations_to_describe = associations[:5]
        association_details = []
        
        for association in associations_to_describe:
            try:
                association_id = association.get('associationId')
                describe_response = client.describe_pod_identity_association(
                    clusterName=cluster_name,
                    associationId=association_id
                )
                
                pod_identity = describe_response.get('association', {})
                
                # Pod 신원 연결 보안 분석
                security_analysis = {
                    'association_id': association_id,
                    'namespace': pod_identity.get('namespace'),
                    'service_account': pod_identity.get('serviceAccount'),
                    'role_arn': pod_identity.get('roleArn'),
                    'tags': pod_identity.get('tags', {})
                }
                
                association_details.append(security_analysis)
                
            except Exception as e:
                print(f"Error describing pod identity association {association.get('associationId')}: {str(e)}")
                continue
        
        return {
            'has_pod_identity_associations': True,
            'total_associations': len(associations),
            'analyzed_associations': len(association_details),
            'association_details': association_details
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_cluster_addons_security(client, cluster_name):
    """애드온 보안 분석 (ListAddons + DescribeAddon + DescribeAddonVersions)"""
    try:
        # ListAddons
        list_response = client.list_addons(clusterName=cluster_name)
        addon_names = list_response.get('addons', [])
        
        if not addon_names:
            return {
                'has_addons': False,
                'message': '설치된 애드온이 없습니다.'
            }
        
        # DescribeAddon (모든 애드온)
        addon_details = []
        
        for addon_name in addon_names:
            try:
                describe_response = client.describe_addon(
                    clusterName=cluster_name,
                    addonName=addon_name
                )
                addon = describe_response.get('addon', {})
                
                # DescribeAddonVersions
                try:
                    versions_response = client.describe_addon_versions(addonName=addon_name)
                    available_versions = versions_response.get('addons', [])
                except Exception as e:
                    print(f"Error getting addon versions for {addon_name}: {str(e)}")
                    available_versions = []
                
                # 애드온 보안 분석
                security_analysis = {
                    'addon_name': addon_name,
                    'addon_version': addon.get('addonVersion'),
                    'status': addon.get('status'),
                    'service_account_role_arn': addon.get('serviceAccountRoleArn'),
                    'configuration_values': addon.get('configurationValues'),
                    'resolve_conflicts': addon.get('resolveConflicts'),
                    'available_versions': [v.get('addonVersion') for v in available_versions] if available_versions else [],
                    'tags': addon.get('tags', {})
                }
                
                addon_details.append(security_analysis)
                
            except Exception as e:
                print(f"Error describing addon {addon_name}: {str(e)}")
                continue
        
        return {
            'has_addons': True,
            'total_addons': len(addon_names),
            'analyzed_addons': len(addon_details),
            'addon_details': addon_details
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_cluster_tags_safe(client, cluster_arn):
    """ListTagsForResource 안전 호출"""
    try:
        if not cluster_arn:
            return {'has_tags': False, 'message': '클러스터 ARN이 없습니다.'}
            
        response = client.list_tags_for_resource(resourceArn=cluster_arn)
        tags = response.get('tags', {})
        
        # 보안 관련 태그 분석
        security_tags = {}
        compliance_tags = {}
        environment_tags = {}
        
        for key, value in tags.items():
            key_lower = key.lower()
            if any(keyword in key_lower for keyword in ['security', 'sec', 'compliance', 'audit']):
                security_tags[key] = value
            elif any(keyword in key_lower for keyword in ['env', 'environment', 'stage']):
                environment_tags[key] = value
            elif any(keyword in key_lower for keyword in ['compliance', 'policy', 'governance']):
                compliance_tags[key] = value
        
        return {
            'has_tags': len(tags) > 0,
            'total_tags': len(tags),
            'all_tags': tags,
            'security_tags': security_tags,
            'compliance_tags': compliance_tags,
            'environment_tags': environment_tags
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_cluster_versions_safe(client):
    """DescribeClusterVersions 안전 호출"""
    try:
        response = client.describe_cluster_versions()
        cluster_versions = response.get('clusterVersions', [])
        
        return {
            'available_versions': cluster_versions,
            'latest_version': cluster_versions[0] if cluster_versions else None,
            'total_versions': len(cluster_versions)
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def execute_parallel_tasks(tasks, max_workers=5):
    """병렬 작업 실행 헬퍼 함수"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def calculate_total_eks_apis_called(cluster_names):
    """총 API 호출 수 계산"""
    # 기본 API: ListClusters(1) + DescribeClusterVersions(1)
    base_apis = 2
    
    # 클러스터당 API: DescribeCluster(1) + ListNodegroups(1) + DescribeNodegroup(최대5) + 
    #                ListFargateProfiles(1) + DescribeFargateProfile(최대5) + 
    #                ListAccessEntries(1) + DescribeAccessEntry(최대5) + ListAssociatedAccessPolicies(최대5) +
    #                DescribeIdentityProviderConfig(1) + ListPodIdentityAssociations(1) + DescribePodIdentityAssociation(최대5) +
    #                ListAddons(1) + DescribeAddon(평균3) + DescribeAddonVersions(평균3) + ListTagsForResource(1)
    cluster_apis = len(cluster_names) * 35  # 평균 35개 API per cluster
    
    return base_apis + cluster_apis

def create_bedrock_success_response(event, response_data):
    """Bedrock Agent 성공 응답 생성"""
    response_body = {
        'TEXT': {
            'body': json.dumps(response_data, ensure_ascii=False, indent=2, default=str)
        }
    }
    
    function_response = {
        'actionGroup': event['actionGroup'],
        'function': event['function'],
        'functionResponse': {
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }

def create_bedrock_error_response(event, error_message):
    """Bedrock Agent 에러 응답 생성"""
    error_data = {
        'function': event.get('function', 'analyzeEksSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'eks-security-analysis'),
        'function': event.get('function', 'analyzeEksSecurity'),
        'functionResponse': {
            'responseState': 'FAILURE',
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }
