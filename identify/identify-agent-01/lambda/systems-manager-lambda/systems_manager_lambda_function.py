import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-01 Systems Manager 보안 분석 Lambda 함수
    Systems Manager의 모든 시스템 보안 관리 상태를 종합 분석
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
        
        ssm_client = session.client('ssm', region_name=target_region)
        
        # Systems Manager 원시 데이터 수집
        raw_data = collect_ssm_raw_data_parallel(ssm_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeSystemsManagerSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Systems Manager 분석 중 오류 발생: {str(e)}"
        print(f"Error in Systems Manager lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ssm_raw_data_parallel(client, target_region):
    """
    Systems Manager 원시 데이터를 병렬로 수집 (37개 API)
    """
    # 병렬 데이터 수집 작업 정의 (37개 API를 9개 카테고리로 분류)
    collection_tasks = [
        # 1. 기본 인스턴스 보안 상태 진단 (4개)
        ('instance_information', lambda: get_instance_information(client)),
        ('instance_properties', lambda: get_instance_properties(client)),
        ('instance_associations_status', lambda: get_instance_associations_status(client)),
        ('effective_instance_associations', lambda: get_effective_instance_associations(client)),
        
        # 2. 보안 패치 관리 진단 (7개)
        ('instance_patches', lambda: get_instance_patches(client)),
        ('instance_patch_states', lambda: get_instance_patch_states(client)),
        ('available_patches', lambda: get_available_patches(client)),
        ('patch_baselines', lambda: get_patch_baselines(client)),
        ('patch_properties', lambda: get_patch_properties(client)),
        ('default_patch_baseline', lambda: get_default_patch_baseline(client)),
        ('patch_baseline_details', lambda: get_patch_baseline_details(client)),
        
        # 3. 보안 규정 준수 모니터링 (3개)
        ('compliance_items', lambda: get_compliance_items(client)),
        ('compliance_summaries', lambda: get_compliance_summaries(client)),
        ('resource_compliance_summaries', lambda: get_resource_compliance_summaries(client)),
        
        # 4. 보안 정보 저장소 관리 (5개)
        ('parameters', lambda: get_parameters(client)),
        ('parameter_details', lambda: get_parameter_details(client)),
        ('parameters_batch', lambda: get_parameters_batch(client)),
        ('parameters_by_path', lambda: get_parameters_by_path(client)),
        ('parameter_history', lambda: get_parameter_history(client)),
        
        # 5. 접근 제어 및 세션 보안 (2개)
        ('sessions', lambda: get_sessions(client)),
        ('connection_status', lambda: get_connection_status(client)),
        
        # 6. 시스템 구성 및 인벤토리 보안 (3개)
        ('inventory', lambda: get_inventory(client)),
        ('inventory_schema', lambda: get_inventory_schema(client)),
        ('inventory_entries', lambda: get_inventory_entries(client)),
        
        # 7. 보안 작업 실행 이력 감사 (3개)
        ('commands', lambda: get_commands(client)),
        ('command_invocations', lambda: get_command_invocations(client)),
        ('command_invocation_details', lambda: get_command_invocation_details(client)),
        
        # 8. 보안 자동화 및 문서 관리 (6개)
        ('automation_executions', lambda: get_automation_executions(client)),
        ('automation_step_executions', lambda: get_automation_step_executions(client)),
        ('automation_execution_details', lambda: get_automation_execution_details(client)),
        ('document_details', lambda: get_document_details(client)),
        ('document_permission', lambda: get_document_permission(client)),
        ('documents', lambda: get_documents(client)),
        
        # 9. 보안 유지보수 스케줄 관리 (4개)
        ('maintenance_window_schedule', lambda: get_maintenance_window_schedule(client)),
        ('maintenance_windows_for_target', lambda: get_maintenance_windows_for_target(client)),
        ('maintenance_window_executions', lambda: get_maintenance_window_executions(client)),
        ('maintenance_window_execution_tasks', lambda: get_maintenance_window_execution_tasks(client))
    ]
    
    # 병렬 처리 실행
    results = process_ssm_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'data_categories_collected': len([k for k, v in results.items() if v is not None and v.get('status') != 'error']),
        'total_apis_called': 37,
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeSystemsManagerSecurity',
        'target_region': target_region,
        'ssm_data': results,
        'collection_summary': collection_summary
    }

def process_ssm_parallel(tasks, max_workers=6):
    """
    Systems Manager 데이터 수집 작업을 병렬로 처리
    """
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
# 1. 기본 인스턴스 보안 상태 진단 (4개)
def get_instance_information(client):
    """DescribeInstanceInformation - SSM 에이전트 상태, 플랫폼 정보, 연결 상태 확인"""
    try:
        response = client.describe_instance_information()
        instances = response.get('InstanceInformationList', [])
        return {
            'status': 'success',
            'total_instances': len(instances),
            'instances': instances[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_instance_properties(client):
    """DescribeInstanceProperties - 인스턴스 속성, IAM 역할, 키 페어 등 보안 설정 조회"""
    try:
        response = client.describe_instance_properties()
        properties = response.get('InstanceProperties', [])
        return {
            'status': 'success',
            'total_properties': len(properties),
            'instance_properties': properties[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_instance_associations_status(client):
    """DescribeInstanceAssociationsStatus - 보안 정책(Association) 적용 상태 및 실행 결과 확인"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 연결 상태 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'association_statuses': [],
                'message': 'No instances found for association status check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.describe_instance_associations_status(InstanceId=first_instance_id)
        
        return {
            'status': 'success',
            'instance_id': first_instance_id,
            'association_statuses': response.get('InstanceAssociationStatusInfos', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_effective_instance_associations(client):
    """DescribeEffectiveInstanceAssociations - 실제 적용된 보안 정책 내용 및 버전 조회"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 효과적인 연결 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'effective_associations': [],
                'message': 'No instances found for effective associations check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.describe_effective_instance_associations(InstanceId=first_instance_id)
        
        return {
            'status': 'success',
            'instance_id': first_instance_id,
            'effective_associations': response.get('Associations', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 2. 보안 패치 관리 진단 (7개)
def get_instance_patches(client):
    """DescribeInstancePatches - 개별 보안 패치 설치 상태, 누락 패치, 심각도 확인"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 패치 상태 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'instance_patches': [],
                'message': 'No instances found for patch check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.describe_instance_patches(InstanceId=first_instance_id)
        
        return {
            'status': 'success',
            'instance_id': first_instance_id,
            'patches': response.get('Patches', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_instance_patch_states(client):
    """DescribeInstancePatchStates - 전체 패치 준수 상태 요약, 중요/보안 패치 미준수 수"""
    try:
        response = client.describe_instance_patch_states()
        patch_states = response.get('InstancePatchStates', [])
        return {
            'status': 'success',
            'total_instances': len(patch_states),
            'patch_states': patch_states[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_available_patches(client):
    """DescribeAvailablePatches - 사용 가능한 보안 패치 목록, 심각도, 출시일 조회"""
    try:
        # 보안 패치만 필터링
        response = client.describe_available_patches(
            Filters=[
                {
                    'Key': 'CLASSIFICATION',
                    'Values': ['Security', 'SecurityUpdates']
                }
            ],
            MaxResults=50  # 최대 50개만 조회
        )
        patches = response.get('Patches', [])
        return {
            'status': 'success',
            'total_security_patches': len(patches),
            'available_patches': patches
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_patch_baselines(client):
    """DescribePatchBaselines - 적용된 패치 정책 목록, AWS 기본/사용자 정의 정책 확인"""
    try:
        response = client.describe_patch_baselines()
        baselines = response.get('BaselineIdentities', [])
        return {
            'status': 'success',
            'total_baselines': len(baselines),
            'patch_baselines': baselines
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_patch_properties(client):
    """DescribePatchProperties - 패치 분류 속성, 보안 업데이트 필터링 기준 조회"""
    try:
        response = client.describe_patch_properties(
            OperatingSystem='WINDOWS',  # Windows 패치 속성 조회
            Property='CLASSIFICATION'
        )
        properties = response.get('Properties', [])
        return {
            'status': 'success',
            'operating_system': 'WINDOWS',
            'property_type': 'CLASSIFICATION',
            'patch_properties': properties
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_default_patch_baseline(client):
    """GetDefaultPatchBaseline - 운영체제별 기본 보안 패치 정책 확인"""
    try:
        response = client.get_default_patch_baseline()
        return {
            'status': 'success',
            'default_baseline_id': response.get('BaselineId', ''),
            'operating_system': response.get('OperatingSystem', '')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_patch_baseline_details(client):
    """GetPatchBaseline - 특정 패치 정책의 승인 규칙, 보안 준수 수준 세부 조회"""
    try:
        # 먼저 기본 패치 베이스라인을 가져와서 상세 정보 조회
        default_response = client.get_default_patch_baseline()
        baseline_id = default_response.get('BaselineId', '')
        
        if not baseline_id:
            return {
                'status': 'success',
                'baseline_details': None,
                'message': 'No default patch baseline found'
            }
        
        response = client.get_patch_baseline(BaselineId=baseline_id)
        
        return {
            'status': 'success',
            'baseline_id': baseline_id,
            'baseline_details': {
                'name': response.get('Name', ''),
                'operating_system': response.get('OperatingSystem', ''),
                'approval_rules': response.get('ApprovalRules', {}),
                'approved_patches': response.get('ApprovedPatches', []),
                'rejected_patches': response.get('RejectedPatches', [])
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 3. 보안 규정 준수 모니터링 (3개)
def get_compliance_items(client):
    """ListComplianceItems - 리소스별 보안 준수 항목, 상태, 심각도 세부 조회"""
    try:
        response = client.list_compliance_items()
        compliance_items = response.get('ComplianceItems', [])
        return {
            'status': 'success',
            'total_compliance_items': len(compliance_items),
            'compliance_items': compliance_items[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_summaries(client):
    """ListComplianceSummaries - 전체 보안 준수 유형별 요약, 준수/미준수 수 통계"""
    try:
        response = client.list_compliance_summaries()
        summaries = response.get('ComplianceSummaryItems', [])
        return {
            'status': 'success',
            'total_summaries': len(summaries),
            'compliance_summaries': summaries
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resource_compliance_summaries(client):
    """ListResourceComplianceSummaries - 리소스별 보안 준수 상태 요약, 심각도별 분류"""
    try:
        response = client.list_resource_compliance_summaries()
        summaries = response.get('ResourceComplianceSummaryItems', [])
        return {
            'status': 'success',
            'total_resource_summaries': len(summaries),
            'resource_compliance_summaries': summaries[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 4. 보안 정보 저장소 관리 (5개)
def get_parameters(client):
    """DescribeParameters - Parameter Store 보안 파라미터 메타데이터, 암호화 상태 조회"""
    try:
        response = client.describe_parameters()
        parameters = response.get('Parameters', [])
        return {
            'status': 'success',
            'total_parameters': len(parameters),
            'parameters': parameters[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_parameter_details(client):
    """GetParameter - 개별 보안 파라미터 값 조회, 암호화된 값 복호화"""
    try:
        # 먼저 파라미터 목록을 가져와서 첫 번째 파라미터의 값 조회
        parameters_response = client.describe_parameters()
        parameters = parameters_response.get('Parameters', [])
        
        if not parameters:
            return {
                'status': 'success',
                'parameter_value': None,
                'message': 'No parameters found'
            }
        
        first_parameter_name = parameters[0]['Name']
        response = client.get_parameter(Name=first_parameter_name)
        
        return {
            'status': 'success',
            'parameter_name': first_parameter_name,
            'parameter_details': response.get('Parameter', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_parameters_batch(client):
    """GetParameters - 여러 보안 파라미터 일괄 조회, 접근 불가 파라미터 확인"""
    try:
        # 먼저 파라미터 목록을 가져와서 처음 5개 파라미터의 값 일괄 조회
        parameters_response = client.describe_parameters()
        parameters = parameters_response.get('Parameters', [])
        
        if not parameters:
            return {
                'status': 'success',
                'parameters_batch': [],
                'message': 'No parameters found for batch retrieval'
            }
        
        parameter_names = [param['Name'] for param in parameters[:5]]
        response = client.get_parameters(Names=parameter_names)
        
        return {
            'status': 'success',
            'requested_parameters': len(parameter_names),
            'valid_parameters': response.get('Parameters', []),
            'invalid_parameters': response.get('InvalidParameters', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_parameters_by_path(client):
    """GetParametersByPath - 경로별 보안 파라미터 그룹 조회, 계층 구조 탐색"""
    try:
        # 일반적인 경로로 파라미터 조회
        response = client.get_parameters_by_path(
            Path='/',
            Recursive=True,
            MaxResults=20
        )
        parameters = response.get('Parameters', [])
        return {
            'status': 'success',
            'path': '/',
            'total_parameters': len(parameters),
            'parameters_by_path': parameters
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_parameter_history(client):
    """GetParameterHistory - 보안 파라미터 변경 이력, 수정자, 변경 시간 추적"""
    try:
        # 먼저 파라미터 목록을 가져와서 첫 번째 파라미터의 이력 조회
        parameters_response = client.describe_parameters()
        parameters = parameters_response.get('Parameters', [])
        
        if not parameters:
            return {
                'status': 'success',
                'parameter_history': [],
                'message': 'No parameters found for history check'
            }
        
        first_parameter_name = parameters[0]['Name']
        response = client.get_parameter_history(Name=first_parameter_name)
        
        return {
            'status': 'success',
            'parameter_name': first_parameter_name,
            'parameter_history': response.get('Parameters', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
# 5. 접근 제어 및 세션 보안 (2개)
def get_sessions(client):
    """DescribeSessions - Session Manager 접근 이력, 세션 소유자, 접근 시간 감사"""
    try:
        response = client.describe_sessions(State='Active')
        sessions = response.get('Sessions', [])
        return {
            'status': 'success',
            'total_active_sessions': len(sessions),
            'active_sessions': sessions
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_connection_status(client):
    """GetConnectionStatus - 인스턴스 Session Manager 연결 가능 상태, 접근성 확인"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 연결 상태 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'connection_status': None,
                'message': 'No instances found for connection status check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.get_connection_status(Target=first_instance_id)
        
        return {
            'status': 'success',
            'target_instance': first_instance_id,
            'connection_status': response.get('Status', ''),
            'target': response.get('Target', '')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 6. 시스템 구성 및 인벤토리 보안 (3개)
def get_inventory(client):
    """GetInventory - 설치된 소프트웨어, 구성 요소, 보안 관련 인벤토리 조회"""
    try:
        response = client.get_inventory()
        entities = response.get('Entities', [])
        return {
            'status': 'success',
            'total_entities': len(entities),
            'inventory_entities': entities[:10]  # 처음 10개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_inventory_schema(client):
    """GetInventorySchema - 수집 가능한 보안 관련 데이터 유형, 속성 구조 확인"""
    try:
        response = client.get_inventory_schema()
        schemas = response.get('Schemas', [])
        return {
            'status': 'success',
            'total_schemas': len(schemas),
            'inventory_schemas': schemas
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_inventory_entries(client):
    """ListInventoryEntries - 특정 인스턴스의 소프트웨어 목록, 버전, 보안 상태 조회"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 인벤토리 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'inventory_entries': [],
                'message': 'No instances found for inventory entries check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.list_inventory_entries(
            InstanceId=first_instance_id,
            TypeName='AWS:Application'  # 설치된 애플리케이션 조회
        )
        
        return {
            'status': 'success',
            'instance_id': first_instance_id,
            'type_name': 'AWS:Application',
            'inventory_entries': response.get('Entries', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 7. 보안 작업 실행 이력 감사 (3개)
def get_commands(client):
    """ListCommands - 실행된 보안 명령 목록, 상태, 실행 시간, 대상 인스턴스 조회"""
    try:
        response = client.list_commands()
        commands = response.get('Commands', [])
        return {
            'status': 'success',
            'total_commands': len(commands),
            'commands': commands[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_command_invocations(client):
    """ListCommandInvocations - 인스턴스별 보안 명령 실행 세부 내역, 결과 확인"""
    try:
        response = client.list_command_invocations()
        invocations = response.get('CommandInvocations', [])
        return {
            'status': 'success',
            'total_invocations': len(invocations),
            'command_invocations': invocations[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_command_invocation_details(client):
    """GetCommandInvocation - 특정 보안 명령 실행 결과 상세, 출력 내용, 오류 분석"""
    try:
        # 먼저 명령 목록을 가져와서 첫 번째 명령의 상세 정보 조회
        commands_response = client.list_commands()
        commands = commands_response.get('Commands', [])
        
        if not commands:
            return {
                'status': 'success',
                'command_invocation': None,
                'message': 'No commands found for invocation details'
            }
        
        first_command = commands[0]
        command_id = first_command['CommandId']
        
        # 해당 명령의 인스턴스 대상 확인
        if not first_command.get('InstanceIds'):
            return {
                'status': 'success',
                'command_invocation': None,
                'message': 'No instance targets found for command'
            }
        
        first_instance_id = first_command['InstanceIds'][0]
        response = client.get_command_invocation(
            CommandId=command_id,
            InstanceId=first_instance_id
        )
        
        return {
            'status': 'success',
            'command_id': command_id,
            'instance_id': first_instance_id,
            'command_invocation': {
                'status': response.get('Status', ''),
                'status_details': response.get('StatusDetails', ''),
                'standard_output_content': response.get('StandardOutputContent', ''),
                'standard_error_content': response.get('StandardErrorContent', '')
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 8. 보안 자동화 및 문서 관리 (6개)
def get_automation_executions(client):
    """DescribeAutomationExecutions - 보안 자동화 작업 실행 이력, 상태, 실행자 확인"""
    try:
        response = client.describe_automation_executions()
        executions = response.get('AutomationExecutionMetadataList', [])
        return {
            'status': 'success',
            'total_executions': len(executions),
            'automation_executions': executions[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_automation_step_executions(client):
    """DescribeAutomationStepExecutions - 자동화 단계별 실행 상태, 입출력 값 세부 조회"""
    try:
        # 먼저 자동화 실행 목록을 가져와서 첫 번째 실행의 단계 조회
        executions_response = client.describe_automation_executions()
        executions = executions_response.get('AutomationExecutionMetadataList', [])
        
        if not executions:
            return {
                'status': 'success',
                'step_executions': [],
                'message': 'No automation executions found for step details'
            }
        
        first_execution_id = executions[0]['AutomationExecutionId']
        response = client.describe_automation_step_executions(AutomationExecutionId=first_execution_id)
        
        return {
            'status': 'success',
            'automation_execution_id': first_execution_id,
            'step_executions': response.get('StepExecutions', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_automation_execution_details(client):
    """GetAutomationExecution - 특정 보안 자동화 작업의 전체 실행 정보, 매개변수 확인"""
    try:
        # 먼저 자동화 실행 목록을 가져와서 첫 번째 실행의 상세 정보 조회
        executions_response = client.describe_automation_executions()
        executions = executions_response.get('AutomationExecutionMetadataList', [])
        
        if not executions:
            return {
                'status': 'success',
                'automation_execution': None,
                'message': 'No automation executions found for details'
            }
        
        first_execution_id = executions[0]['AutomationExecutionId']
        response = client.get_automation_execution(AutomationExecutionId=first_execution_id)
        
        return {
            'status': 'success',
            'automation_execution_id': first_execution_id,
            'automation_execution': response.get('AutomationExecution', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_document_details(client):
    """DescribeDocument - 보안 관련 문서/런북 정보, 매개변수, 지원 플랫폼 조회"""
    try:
        # AWS 제공 보안 관련 문서 조회
        response = client.describe_document(Name='AWSSupport-ExecuteEC2Rescue')
        return {
            'status': 'success',
            'document_name': 'AWSSupport-ExecuteEC2Rescue',
            'document_details': {
                'name': response.get('Document', {}).get('Name', ''),
                'document_type': response.get('Document', {}).get('DocumentType', ''),
                'platform_types': response.get('Document', {}).get('PlatformTypes', []),
                'parameters': response.get('Document', {}).get('Parameters', [])
            }
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_document_permission(client):
    """DescribeDocumentPermission - 보안 문서 접근 권한, 공유 상태, 계정별 권한 확인"""
    try:
        # AWS 제공 보안 관련 문서의 권한 조회
        response = client.describe_document_permission(
            Name='AWSSupport-ExecuteEC2Rescue',
            PermissionType='Share'
        )
        return {
            'status': 'success',
            'document_name': 'AWSSupport-ExecuteEC2Rescue',
            'permission_type': 'Share',
            'account_ids': response.get('AccountIds', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_documents(client):
    """ListDocuments - 사용 가능한 보안 문서 목록, 소유자, 유형, 태그 조회"""
    try:
        response = client.list_documents(
            DocumentFilterList=[
                {
                    'key': 'DocumentType',
                    'value': 'Automation'
                }
            ]
        )
        documents = response.get('DocumentIdentifiers', [])
        return {
            'status': 'success',
            'document_type': 'Automation',
            'total_documents': len(documents),
            'documents': documents[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 9. 보안 유지보수 스케줄 관리 (4개)
def get_maintenance_window_schedule(client):
    """DescribeMaintenanceWindowSchedule - 예정된 보안 패치 일정, 실행 시간 확인"""
    try:
        response = client.describe_maintenance_window_schedule()
        scheduled_windows = response.get('ScheduledWindowExecutions', [])
        return {
            'status': 'success',
            'total_scheduled_windows': len(scheduled_windows),
            'scheduled_windows': scheduled_windows[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_maintenance_windows_for_target(client):
    """DescribeMaintenanceWindowsForTarget - 인스턴스에 적용된 유지보수 창 목록 조회"""
    try:
        # 먼저 인스턴스 목록을 가져와서 첫 번째 인스턴스의 유지보수 창 조회
        instances_response = client.describe_instance_information()
        instances = instances_response.get('InstanceInformationList', [])
        
        if not instances:
            return {
                'status': 'success',
                'maintenance_windows': [],
                'message': 'No instances found for maintenance windows check'
            }
        
        first_instance_id = instances[0]['InstanceId']
        response = client.describe_maintenance_windows_for_target(
            Targets=[
                {
                    'Key': 'InstanceIds',
                    'Values': [first_instance_id]
                }
            ]
        )
        
        return {
            'status': 'success',
            'target_instance': first_instance_id,
            'maintenance_windows': response.get('WindowIdentities', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_maintenance_window_executions(client):
    """DescribeMaintenanceWindowExecutions - 보안 패치 유지보수 실행 이력, 성공/실패 상태 확인"""
    try:
        # 먼저 유지보수 창 목록을 가져와서 첫 번째 창의 실행 이력 조회
        windows_response = client.describe_maintenance_windows()
        windows = windows_response.get('WindowIdentities', [])
        
        if not windows:
            return {
                'status': 'success',
                'window_executions': [],
                'message': 'No maintenance windows found for execution history'
            }
        
        first_window_id = windows[0]['WindowId']
        response = client.describe_maintenance_window_executions(WindowId=first_window_id)
        
        return {
            'status': 'success',
            'window_id': first_window_id,
            'window_executions': response.get('WindowExecutions', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_maintenance_window_execution_tasks(client):
    """DescribeMaintenanceWindowExecutionTasks - 유지보수 창 내 개별 보안 작업 실행 상태 조회"""
    try:
        # 먼저 유지보수 창과 실행을 가져와서 첫 번째 실행의 작업 조회
        windows_response = client.describe_maintenance_windows()
        windows = windows_response.get('WindowIdentities', [])
        
        if not windows:
            return {
                'status': 'success',
                'execution_tasks': [],
                'message': 'No maintenance windows found for execution tasks'
            }
        
        first_window_id = windows[0]['WindowId']
        executions_response = client.describe_maintenance_window_executions(WindowId=first_window_id)
        executions = executions_response.get('WindowExecutions', [])
        
        if not executions:
            return {
                'status': 'success',
                'execution_tasks': [],
                'message': 'No window executions found for tasks'
            }
        
        first_execution_id = executions[0]['WindowExecutionId']
        response = client.describe_maintenance_window_execution_tasks(
            WindowId=first_window_id,
            WindowExecutionId=first_execution_id
        )
        
        return {
            'status': 'success',
            'window_id': first_window_id,
            'execution_id': first_execution_id,
            'execution_tasks': response.get('WindowExecutionTaskIdentities', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def create_bedrock_success_response(event, response_data):
    """
    Bedrock Agent 성공 응답 생성
    """
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
    """
    Bedrock Agent 에러 응답 생성
    """
    error_data = {
        'function': event.get('function', 'analyzeSystemsManagerSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'systems-manager-analysis'),
        'function': event.get('function', 'analyzeSystemsManagerSecurity'),
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
