import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 Computing Resources Discovery Lambda 함수
    컴퓨팅 리소스 (EC2, Lambda, ECS, ECR, EKS) 존재 여부 확인
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
        
        # 컴퓨팅 리소스 발견
        discovery_results = discover_computing_resources_parallel(session, target_region, current_time)
        
        # 응답 데이터 구성
        total_services_with_resources = sum(1 for service in discovery_results.values() if service.get('has_resources', False))
        
        response_data = {
            'function': 'discoverComputingResources',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': total_services_with_resources,
                'discovery_method': 'parallel_processing',
                'agent_type': 'identify-agent-02',
                'focus': 'computing_resource_security_identification_ec2_lambda_ecs_ecr_eks'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"컴퓨팅 리소스 Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in identify-agent-02 computing resource discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_computing_resources_parallel(session, target_region, current_time):
    """
    컴퓨팅 리소스 (EC2 + Lambda + ECS + ECR + EKS) 병렬 발견
    """
    services_to_check = [
        ('ec2', discover_ec2_resources),
        ('lambda', discover_lambda_resources),
        ('ecs', discover_ecs_resources),
        ('ecr', discover_ecr_resources),
        ('eks', discover_eks_resources)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_service = {
            executor.submit(discover_func, session, target_region, current_time): service_name 
            for service_name, discover_func in services_to_check
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error discovering {service_name}: {str(e)}")
                results[service_name] = {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def discover_ec2_resources(session, target_region, current_time):
    """EC2 인스턴스 및 관련 리소스 발견"""
    try:
        ec2_client = session.client('ec2', region_name=target_region)
        
        # EC2 인스턴스 목록 조회
        instances_response = ec2_client.describe_instances()
        reservations = instances_response.get('Reservations', [])
        
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
        
        if not all_instances:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['instances'],
                'status': 'no_instances',
                'details': {
                    'note': 'EC2 인스턴스가 존재하지 않습니다.'
                }
            }
        
        # 인스턴스 상태별 분류
        running_instances = [i for i in all_instances if i.get('State', {}).get('Name') == 'running']
        stopped_instances = [i for i in all_instances if i.get('State', {}).get('Name') == 'stopped']
        
        # 퍼블릭 IP 할당된 인스턴스 수
        public_ip_instances = [i for i in all_instances if i.get('PublicIpAddress')]
        
        # 인스턴스 타입별 분류
        instance_type_stats = {}
        for instance in all_instances:
            instance_type = instance.get('InstanceType', 'Unknown')
            instance_type_stats[instance_type] = instance_type_stats.get(instance_type, 0) + 1
        
        # 추가 리소스 수 집계
        volumes_response = ec2_client.describe_volumes()
        total_volumes = len(volumes_response.get('Volumes', []))
        
        security_groups_response = ec2_client.describe_security_groups()
        total_security_groups = len(security_groups_response.get('SecurityGroups', []))
        
        return {
            'has_resources': len(running_instances) > 0,
            'resource_count': len(all_instances),
            'resource_types': ['instances', 'volumes', 'security_groups'],
            'status': 'active' if running_instances else 'no_running_instances',
            'details': {
                'total_instances': len(all_instances),
                'running_instances': len(running_instances),
                'stopped_instances': len(stopped_instances),
                'public_ip_instances': len(public_ip_instances),
                'total_volumes': total_volumes,
                'total_security_groups': total_security_groups,
                'instance_type_distribution': instance_type_stats,
                'sample_instance_ids': [i['InstanceId'] for i in running_instances[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering EC2 resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_lambda_resources(session, target_region, current_time):
    """Lambda 함수 리소스 발견"""
    try:
        lambda_client = session.client('lambda', region_name=target_region)
        
        # Lambda 함수 목록 조회
        response = lambda_client.list_functions()
        functions = response.get('Functions', [])
        
        if not functions:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['functions'],
                'status': 'no_functions',
                'details': {
                    'note': 'Lambda 함수가 존재하지 않습니다.'
                }
            }
        
        # 함수 상태별 분류
        active_functions = [f for f in functions if f.get('State') == 'Active']
        pending_functions = [f for f in functions if f.get('State') == 'Pending']
        inactive_functions = [f for f in functions if f.get('State') == 'Inactive']
        failed_functions = [f for f in functions if f.get('State') == 'Failed']
        
        # 런타임별 분류
        runtime_stats = {}
        for func in functions:
            runtime = func.get('Runtime', 'Unknown')
            runtime_stats[runtime] = runtime_stats.get(runtime, 0) + 1
        
        return {
            'has_resources': len(active_functions) > 0,
            'resource_count': len(functions),
            'resource_types': ['functions'],
            'status': 'active' if active_functions else 'no_active_functions',
            'details': {
                'total_functions': len(functions),
                'active_functions': len(active_functions),
                'pending_functions': len(pending_functions),
                'inactive_functions': len(inactive_functions),
                'failed_functions': len(failed_functions),
                'runtime_distribution': runtime_stats,
                'sample_function_names': [f['FunctionName'] for f in active_functions[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering Lambda resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }
def discover_ecs_resources(session, target_region, current_time):
    """ECS 클러스터 및 서비스 리소스 발견"""
    try:
        ecs_client = session.client('ecs', region_name=target_region)
        
        # ECS 클러스터 목록 조회
        clusters_response = ecs_client.list_clusters()
        cluster_arns = clusters_response.get('clusterArns', [])
        
        if not cluster_arns:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['clusters'],
                'status': 'no_clusters',
                'details': {
                    'note': 'ECS 클러스터가 존재하지 않습니다.'
                }
            }
        
        # 클러스터 상세 정보 조회 (최대 10개)
        clusters_to_describe = cluster_arns[:10]
        clusters_details = []
        total_services = 0
        total_tasks = 0
        
        try:
            describe_response = ecs_client.describe_clusters(clusters=clusters_to_describe)
            clusters_details = describe_response.get('clusters', [])
            
            # 각 클러스터의 서비스 및 태스크 수 집계
            for cluster in clusters_details:
                total_services += cluster.get('activeServicesCount', 0)
                total_tasks += cluster.get('runningTasksCount', 0) + cluster.get('pendingTasksCount', 0)
        except Exception as e:
            print(f"Error describing ECS clusters: {str(e)}")
        
        # 클러스터 상태별 분류
        active_clusters = [c for c in clusters_details if c.get('status') == 'ACTIVE']
        inactive_clusters = [c for c in clusters_details if c.get('status') != 'ACTIVE']
        
        # 런치 타입별 분류
        fargate_clusters = []
        ec2_clusters = []
        for cluster in clusters_details:
            capacity_providers = cluster.get('capacityProviders', [])
            if 'FARGATE' in capacity_providers or 'FARGATE_SPOT' in capacity_providers:
                fargate_clusters.append(cluster)
            if 'EC2' in capacity_providers or any('EC2' in cp for cp in capacity_providers):
                ec2_clusters.append(cluster)
        
        return {
            'has_resources': len(active_clusters) > 0,
            'resource_count': len(cluster_arns),
            'resource_types': ['clusters', 'services', 'tasks'],
            'status': 'active' if active_clusters else 'no_active_clusters',
            'details': {
                'total_clusters': len(cluster_arns),
                'active_clusters': len(active_clusters),
                'inactive_clusters': len(inactive_clusters),
                'total_services': total_services,
                'total_tasks': total_tasks,
                'fargate_clusters': len(fargate_clusters),
                'ec2_clusters': len(ec2_clusters),
                'sample_cluster_names': [c.get('clusterName', 'Unknown') for c in clusters_details[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering ECS resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_ecr_resources(session, target_region, current_time):
    """ECR 리포지토리 리소스 발견"""
    try:
        ecr_client = session.client('ecr', region_name=target_region)
        
        # ECR 리포지토리 목록 조회
        repositories_response = ecr_client.describe_repositories()
        repositories = repositories_response.get('repositories', [])
        
        if not repositories:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['repositories'],
                'status': 'no_repositories',
                'details': {
                    'note': 'ECR 리포지토리가 존재하지 않습니다.'
                }
            }
        
        # 리포지토리별 이미지 수 집계
        total_images = 0
        encrypted_repos = 0
        scan_enabled_repos = 0
        
        for repo in repositories:
            # 암호화 설정 확인
            if repo.get('encryptionConfiguration', {}).get('encryptionType') == 'KMS':
                encrypted_repos += 1
            
            # 스캔 설정 확인
            if repo.get('imageScanningConfiguration', {}).get('scanOnPush'):
                scan_enabled_repos += 1
            
            # 이미지 수 집계 (샘플링)
            try:
                images_response = ecr_client.list_images(
                    repositoryName=repo['repositoryName'],
                    maxResults=10
                )
                total_images += len(images_response.get('imageIds', []))
            except Exception as e:
                print(f"Error counting images in {repo['repositoryName']}: {str(e)}")
        
        return {
            'has_resources': len(repositories) > 0,
            'resource_count': len(repositories),
            'resource_types': ['repositories', 'images'],
            'status': 'active',
            'details': {
                'total_repositories': len(repositories),
                'total_images_sampled': total_images,
                'encrypted_repositories': encrypted_repos,
                'scan_enabled_repositories': scan_enabled_repos,
                'sample_repository_names': [r['repositoryName'] for r in repositories[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering ECR resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_eks_resources(session, target_region, current_time):
    """EKS 클러스터 리소스 발견"""
    try:
        eks_client = session.client('eks', region_name=target_region)
        
        # EKS 클러스터 목록 조회
        clusters_response = eks_client.list_clusters()
        cluster_names = clusters_response.get('clusters', [])
        
        if not cluster_names:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['clusters'],
                'status': 'no_clusters',
                'details': {
                    'note': 'EKS 클러스터가 존재하지 않습니다.'
                }
            }
        
        # 클러스터 상세 정보 조회 (최대 5개)
        clusters_to_describe = cluster_names[:5]
        cluster_details = []
        total_nodegroups = 0
        total_fargate_profiles = 0
        
        for cluster_name in clusters_to_describe:
            try:
                cluster_response = eks_client.describe_cluster(name=cluster_name)
                cluster = cluster_response.get('cluster', {})
                cluster_details.append(cluster)
                
                # 노드그룹 수 집계
                nodegroups_response = eks_client.list_nodegroups(clusterName=cluster_name)
                total_nodegroups += len(nodegroups_response.get('nodegroups', []))
                
                # Fargate 프로필 수 집계
                fargate_response = eks_client.list_fargate_profiles(clusterName=cluster_name)
                total_fargate_profiles += len(fargate_response.get('fargateProfileNames', []))
                
            except Exception as e:
                print(f"Error describing EKS cluster {cluster_name}: {str(e)}")
        
        # 클러스터 상태별 분류
        active_clusters = [c for c in cluster_details if c.get('status') == 'ACTIVE']
        
        # Kubernetes 버전별 분류
        version_stats = {}
        for cluster in cluster_details:
            version = cluster.get('version', 'Unknown')
            version_stats[version] = version_stats.get(version, 0) + 1
        
        return {
            'has_resources': len(active_clusters) > 0,
            'resource_count': len(cluster_names),
            'resource_types': ['clusters', 'nodegroups', 'fargate_profiles'],
            'status': 'active' if active_clusters else 'no_active_clusters',
            'details': {
                'total_clusters': len(cluster_names),
                'active_clusters': len(active_clusters),
                'total_nodegroups': total_nodegroups,
                'total_fargate_profiles': total_fargate_profiles,
                'kubernetes_versions': version_stats,
                'sample_cluster_names': cluster_names[:5],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering EKS resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

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
        'function': event.get('function', 'discoverComputingResources'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'computing-discovery'),
        'function': event.get('function', 'discoverComputingResources'),
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
