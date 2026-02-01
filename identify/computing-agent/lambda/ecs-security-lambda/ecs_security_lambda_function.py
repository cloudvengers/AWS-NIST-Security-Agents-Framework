import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 ECS Security Analysis Lambda 함수
    11개 ECS API를 통한 종합적인 ECS 보안 상태 분석
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
        
        ecs_client = session.client('ecs', region_name=target_region)
        
        # ECS 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_ecs_security_data_parallel(ecs_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEcsSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"ECS 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in ECS security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ecs_security_data_parallel(client, target_region, current_time):
    """
    ECS 보안 데이터를 병렬로 수집 - 11개 API 활용
    """
    # 먼저 클러스터 목록 조회
    try:
        clusters_response = client.list_clusters()
        cluster_arns = clusters_response.get('clusterArns', [])
    except Exception as e:
        print(f"Error listing ECS clusters: {str(e)}")
        return {
            'function': 'analyzeEcsSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'ECS 클러스터 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'clusters_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not cluster_arns:
        return {
            'function': 'analyzeEcsSecurity',
            'target_region': target_region,
            'status': 'no_clusters',
            'message': 'ECS 클러스터가 존재하지 않습니다.',
            'collection_summary': {
                'clusters_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('clusters_security_analysis', lambda: analyze_clusters_security_parallel(client, cluster_arns)),
        ('task_definitions_analysis', lambda: analyze_task_definitions_security_parallel(client)),
    ]
    
    # 병렬 처리 실행
    results = process_ecs_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'clusters_analyzed': len(cluster_arns),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_ecs_apis_called(cluster_arns),
        'collection_method': 'parallel_processing',
        'cluster_arns_analyzed': cluster_arns[:5]  # 최대 5개만 표시
    }
    
    return {
        'function': 'analyzeEcsSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'clusters_data': results.get('clusters_security_analysis', {}),
        'task_definitions_data': results.get('task_definitions_analysis', {}),
        'collection_summary': collection_summary
    }

def process_ecs_parallel(tasks, max_workers=2):
    """ECS 데이터 수집 작업을 병렬로 처리"""
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

def analyze_clusters_security_parallel(client, cluster_arns, max_workers=3):
    """클러스터들의 보안 설정을 병렬로 분석"""
    cluster_analyses = []
    
    # 클러스터를 그룹으로 나누어 처리 (API 제한 고려)
    cluster_groups = [cluster_arns[i:i+10] for i in range(0, len(cluster_arns), 10)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_cluster_group_security, client, group) for group in cluster_groups]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    cluster_analyses.extend(result)
            except Exception as e:
                print(f"Error analyzing cluster group: {str(e)}")
                continue
    
    return {
        'total_clusters_analyzed': len(cluster_analyses),
        'cluster_security_details': cluster_analyses
    }

def analyze_cluster_group_security(client, cluster_arns):
    """클러스터 그룹의 보안 설정 분석"""
    try:
        # 클러스터 상세 정보 조회 (DescribeClusters)
        describe_response = client.describe_clusters(clusters=cluster_arns)
        clusters = describe_response.get('clusters', [])
        
        cluster_analyses = []
        
        for cluster in clusters:
            cluster_name = cluster.get('clusterName')
            cluster_arn = cluster.get('clusterArn')
            
            # 각 클러스터별 보안 분석
            cluster_security_data = analyze_single_cluster_security(client, cluster)
            
            cluster_analyses.append({
                'cluster_name': cluster_name,
                'cluster_arn': cluster_arn,
                'status': cluster.get('status'),
                'capacity_providers': cluster.get('capacityProviders', []),
                'security_analysis': cluster_security_data
            })
        
        return cluster_analyses
        
    except Exception as e:
        print(f"Error analyzing cluster group: {str(e)}")
        return []

def analyze_single_cluster_security(client, cluster):
    """개별 클러스터의 보안 설정 종합 분석"""
    cluster_name = cluster.get('clusterName')
    cluster_arn = cluster.get('clusterArn')
    
    try:
        # 클러스터 보안 분석 데이터 수집
        security_tasks = [
            ('container_instances', lambda: get_container_instances_security(client, cluster_name)),
            ('services', lambda: get_services_security(client, cluster_name)),
            ('tasks', lambda: get_tasks_security(client, cluster_name)),
            ('tags', lambda: get_cluster_tags_security(client, cluster_arn))
        ]
        
        security_data = execute_parallel_tasks(security_tasks, max_workers=4)
        
        # 클러스터 기본 보안 설정 분석
        basic_security = analyze_cluster_basic_security(cluster)
        
        return {
            'basic_security': basic_security,
            'container_instances': security_data.get('container_instances', {}),
            'services': security_data.get('services', {}),
            'tasks': security_data.get('tasks', {}),
            'tags': security_data.get('tags', {})
        }
        
    except Exception as e:
        print(f"Error analyzing cluster {cluster_name}: {str(e)}")
        return {
            'status': 'error',
            'error_message': str(e)
        }

def analyze_cluster_basic_security(cluster):
    """클러스터 기본 보안 설정 분석"""
    return {
        'encryption_at_rest': cluster.get('configuration', {}).get('executeCommandConfiguration', {}).get('kmsKeyId') is not None,
        'logging_enabled': cluster.get('configuration', {}).get('executeCommandConfiguration', {}).get('logging') != 'NONE',
        'capacity_providers': cluster.get('capacityProviders', []),
        'default_capacity_provider_strategy': cluster.get('defaultCapacityProviderStrategy', []),
        'settings': cluster.get('settings', []),
        'configuration': cluster.get('configuration', {})
    }
def get_container_instances_security(client, cluster_name):
    """컨테이너 인스턴스 보안 설정 조회 (2개 API)"""
    try:
        # ListContainerInstances
        list_response = client.list_container_instances(cluster=cluster_name)
        instance_arns = list_response.get('containerInstanceArns', [])
        
        if not instance_arns:
            return {
                'has_container_instances': False,
                'message': '컨테이너 인스턴스가 없습니다.'
            }
        
        # DescribeContainerInstances (최대 10개)
        instances_to_describe = instance_arns[:10]
        describe_response = client.describe_container_instances(
            cluster=cluster_name,
            containerInstances=instances_to_describe
        )
        
        instances = describe_response.get('containerInstances', [])
        
        # 보안 관련 정보 추출
        security_analysis = []
        for instance in instances:
            security_analysis.append({
                'instance_arn': instance.get('containerInstanceArn'),
                'ec2_instance_id': instance.get('ec2InstanceId'),
                'status': instance.get('status'),
                'agent_connected': instance.get('agentConnected'),
                'agent_version': instance.get('versionInfo', {}).get('agentVersion'),
                'docker_version': instance.get('versionInfo', {}).get('dockerVersion'),
                'attributes': instance.get('attributes', []),
                'tags': instance.get('tags', [])
            })
        
        return {
            'has_container_instances': True,
            'total_instances': len(instance_arns),
            'instances_analyzed': len(instances),
            'security_details': security_analysis
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_services_security(client, cluster_name):
    """서비스 보안 설정 조회 (2개 API)"""
    try:
        # ListServices
        list_response = client.list_services(cluster=cluster_name)
        service_arns = list_response.get('serviceArns', [])
        
        if not service_arns:
            return {
                'has_services': False,
                'message': '서비스가 없습니다.'
            }
        
        # DescribeServices (최대 10개)
        services_to_describe = service_arns[:10]
        describe_response = client.describe_services(
            cluster=cluster_name,
            services=services_to_describe
        )
        
        services = describe_response.get('services', [])
        
        # 보안 관련 정보 추출
        security_analysis = []
        for service in services:
            network_config = service.get('networkConfiguration', {}).get('awsvpcConfiguration', {})
            
            security_analysis.append({
                'service_name': service.get('serviceName'),
                'service_arn': service.get('serviceArn'),
                'status': service.get('status'),
                'task_definition': service.get('taskDefinition'),
                'desired_count': service.get('desiredCount'),
                'running_count': service.get('runningCount'),
                'launch_type': service.get('launchType'),
                'platform_version': service.get('platformVersion'),
                'network_security': {
                    'subnets': network_config.get('subnets', []),
                    'security_groups': network_config.get('securityGroups', []),
                    'assign_public_ip': network_config.get('assignPublicIp', 'DISABLED')
                },
                'load_balancers': service.get('loadBalancers', []),
                'service_registries': service.get('serviceRegistries', []),
                'tags': service.get('tags', [])
            })
        
        return {
            'has_services': True,
            'total_services': len(service_arns),
            'services_analyzed': len(services),
            'security_details': security_analysis
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_tasks_security(client, cluster_name):
    """실행 태스크 보안 설정 조회 (2개 API)"""
    try:
        # ListTasks
        list_response = client.list_tasks(cluster=cluster_name)
        task_arns = list_response.get('taskArns', [])
        
        if not task_arns:
            return {
                'has_tasks': False,
                'message': '실행 중인 태스크가 없습니다.'
            }
        
        # DescribeTasks (최대 10개)
        tasks_to_describe = task_arns[:10]
        describe_response = client.describe_tasks(
            cluster=cluster_name,
            tasks=tasks_to_describe
        )
        
        tasks = describe_response.get('tasks', [])
        
        # 보안 관련 정보 추출
        security_analysis = []
        for task in tasks:
            security_analysis.append({
                'task_arn': task.get('taskArn'),
                'task_definition_arn': task.get('taskDefinitionArn'),
                'cluster_arn': task.get('clusterArn'),
                'last_status': task.get('lastStatus'),
                'desired_status': task.get('desiredStatus'),
                'launch_type': task.get('launchType'),
                'platform_version': task.get('platformVersion'),
                'cpu': task.get('cpu'),
                'memory': task.get('memory'),
                'connectivity': task.get('connectivity'),
                'connectivity_at': task.get('connectivityAt'),
                'pull_started_at': task.get('pullStartedAt'),
                'pull_stopped_at': task.get('pullStoppedAt'),
                'execution_stopped_at': task.get('executionStoppedAt'),
                'containers': [
                    {
                        'name': container.get('name'),
                        'last_status': container.get('lastStatus'),
                        'health_status': container.get('healthStatus'),
                        'network_bindings': container.get('networkBindings', []),
                        'network_interfaces': container.get('networkInterfaces', [])
                    }
                    for container in task.get('containers', [])
                ],
                'tags': task.get('tags', [])
            })
        
        return {
            'has_tasks': True,
            'total_tasks': len(task_arns),
            'tasks_analyzed': len(tasks),
            'security_details': security_analysis
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_cluster_tags_security(client, cluster_arn):
    """클러스터 태그 보안 설정 조회 (1개 API)"""
    try:
        # ListTagsForResource
        response = client.list_tags_for_resource(resourceArn=cluster_arn)
        tags = response.get('tags', [])
        
        # 보안 관련 태그 분석
        security_tags = []
        compliance_tags = []
        environment_tags = []
        
        for tag in tags:
            key = tag.get('key', '').lower()
            if any(keyword in key for keyword in ['security', 'sec', 'compliance', 'audit']):
                security_tags.append(tag)
            elif any(keyword in key for keyword in ['env', 'environment', 'stage']):
                environment_tags.append(tag)
            elif any(keyword in key for keyword in ['compliance', 'policy', 'governance']):
                compliance_tags.append(tag)
        
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

def analyze_task_definitions_security_parallel(client):
    """태스크 정의 보안 설정 분석 (2개 API)"""
    try:
        # ListTaskDefinitions
        list_response = client.list_task_definitions()
        task_definition_arns = list_response.get('taskDefinitionArns', [])
        
        if not task_definition_arns:
            return {
                'has_task_definitions': False,
                'message': '태스크 정의가 없습니다.'
            }
        
        # 최신 태스크 정의들만 분석 (최대 10개)
        latest_task_definitions = task_definition_arns[-10:]
        
        task_def_analyses = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(analyze_single_task_definition, client, td_arn) for td_arn in latest_task_definitions]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        task_def_analyses.append(result)
                except Exception as e:
                    print(f"Error analyzing task definition: {str(e)}")
                    continue
        
        return {
            'has_task_definitions': True,
            'total_task_definitions': len(task_definition_arns),
            'analyzed_task_definitions': len(task_def_analyses),
            'task_definition_security_details': task_def_analyses
        }
        
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_single_task_definition(client, task_definition_arn):
    """개별 태스크 정의 보안 분석 (DescribeTaskDefinition)"""
    try:
        response = client.describe_task_definition(taskDefinition=task_definition_arn)
        task_definition = response.get('taskDefinition', {})
        
        # 보안 관련 설정 분석
        security_analysis = {
            'family': task_definition.get('family'),
            'revision': task_definition.get('revision'),
            'status': task_definition.get('status'),
            'task_role_arn': task_definition.get('taskRoleArn'),
            'execution_role_arn': task_definition.get('executionRoleArn'),
            'network_mode': task_definition.get('networkMode'),
            'requires_compatibilities': task_definition.get('requiresCompatibilities', []),
            'cpu': task_definition.get('cpu'),
            'memory': task_definition.get('memory'),
            'pid_mode': task_definition.get('pidMode'),
            'ipc_mode': task_definition.get('ipcMode'),
            'proxy_configuration': task_definition.get('proxyConfiguration'),
            'inference_accelerators': task_definition.get('inferenceAccelerators', []),
            'ephemeral_storage': task_definition.get('ephemeralStorage'),
            'runtime_platform': task_definition.get('runtimePlatform'),
            'container_security_analysis': []
        }
        
        # 컨테이너별 보안 설정 분석
        containers = task_definition.get('containerDefinitions', [])
        for container in containers:
            container_security = {
                'name': container.get('name'),
                'image': container.get('image'),
                'cpu': container.get('cpu'),
                'memory': container.get('memory'),
                'memory_reservation': container.get('memoryReservation'),
                'essential': container.get('essential'),
                'port_mappings': container.get('portMappings', []),
                'environment': len(container.get('environment', [])),
                'secrets': len(container.get('secrets', [])),
                'mount_points': container.get('mountPoints', []),
                'volumes_from': container.get('volumesFrom', []),
                'linux_parameters': container.get('linuxParameters'),
                'log_configuration': container.get('logConfiguration'),
                'health_check': container.get('healthCheck'),
                'system_controls': container.get('systemControls', []),
                'resource_requirements': container.get('resourceRequirements', []),
                'firelensconfiguration': container.get('firelensConfiguration'),
                'credential_specs': container.get('credentialSpecs', [])
            }
            security_analysis['container_security_analysis'].append(container_security)
        
        return security_analysis
        
    except Exception as e:
        print(f"Error analyzing task definition {task_definition_arn}: {str(e)}")
        return {
            'task_definition_arn': task_definition_arn,
            'status': 'error',
            'error_message': str(e)
        }
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

def calculate_total_ecs_apis_called(cluster_arns):
    """총 API 호출 수 계산"""
    # 기본 API: ListClusters(1) + ListTaskDefinitions(1)
    base_apis = 2
    
    # 클러스터당 API: DescribeClusters(1) + ListContainerInstances(1) + DescribeContainerInstances(1) + 
    #                ListServices(1) + DescribeServices(1) + ListTasks(1) + DescribeTasks(1) + ListTagsForResource(1)
    cluster_apis = len(cluster_arns) * 8
    
    # 태스크 정의 API: DescribeTaskDefinition (최대 10개)
    task_def_apis = min(10, len(cluster_arns) * 2)  # 클러스터당 평균 2개 태스크 정의 가정
    
    return base_apis + cluster_apis + task_def_apis

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
        'function': event.get('function', 'analyzeEcsSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'ecs-security-analysis'),
        'function': event.get('function', 'analyzeEcsSecurity'),
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
