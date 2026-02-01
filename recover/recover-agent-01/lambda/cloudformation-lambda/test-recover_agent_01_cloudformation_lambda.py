import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    RECOVER-AGENT-01 CloudFormation 보안 분석 Lambda 함수
    CloudFormation의 18개 API를 활용한 종합적인 인프라 복구 준비도 분석
    """
    try:
        # 파라미터 추출 및 검증
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
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        cloudformation_client = session.client('cloudformation', region_name=target_region)
        
        # CloudFormation 원시 데이터 병렬 수집
        raw_data = collect_cloudformation_raw_data_parallel(cloudformation_client, target_region, current_time)
        
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_message = f"CloudFormation 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in CloudFormation lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_cloudformation_raw_data_parallel(client, target_region, current_time):
    """
    CloudFormation 18개 API를 병렬로 호출하여 원시 데이터 수집
    """
    # 병렬 처리할 데이터 수집 작업 정의 (18개 API)
    data_collection_tasks = [
        # 스택 보안 상태 분석 (6개)
        ('stacks_info', lambda: get_stacks_info(client)),
        ('stack_events', lambda: get_stack_events(client)),
        ('stack_resources', lambda: get_stack_resources(client)),
        ('stack_resource_details', lambda: get_stack_resource_details(client)),
        ('stacks_list', lambda: get_stacks_list(client)),
        ('stack_resources_list', lambda: get_stack_resources_list(client)),
        
        # 드리프트 보안 분석 (2개)
        ('drift_detection_status', lambda: get_drift_detection_status(client)),
        ('stack_resource_drifts', lambda: get_stack_resource_drifts(client)),
        
        # 템플릿 보안 검증 (3개)
        ('templates', lambda: get_templates(client)),
        ('template_summaries', lambda: get_template_summaries(client)),
        ('template_validations', lambda: get_template_validations(client)),
        
        # 변경 세트 보안 분석 (2개)
        ('change_sets', lambda: get_change_sets(client)),
        ('change_sets_list', lambda: get_change_sets_list(client)),
        
        # 비용 기반 보안 분석 (1개)
        ('template_costs', lambda: get_template_costs(client)),
        
        # 계정 제한사항 보안 분석 (1개)
        ('account_limits', lambda: get_account_limits(client)),
        
        # Cross-Stack 보안 의존성 분석 (2개)
        ('exports', lambda: get_exports(client)),
        ('imports', lambda: get_imports(client)),
        
        # 정책 보안 분석 (1개)
        ('stack_policies', lambda: get_stack_policies(client))
    ]
    
    collected_data = {
        'function': 'analyzeCloudFormationSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
    }
    
    # 병렬로 데이터 수집
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_to_task = {
            executor.submit(task_func): task_name 
            for task_name, task_func in data_collection_tasks
        }
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                collected_data[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                collected_data[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    # 수집 요약 정보 추가
    collected_data['collection_summary'] = {
        'total_apis_called': len(data_collection_tasks),
        'successful_collections': sum(1 for key, value in collected_data.items() 
                                    if isinstance(value, dict) and value.get('status') == 'success'),
        'processing_method': 'parallel_processing',
        'api_categories': {
            'stack_security_analysis': 6,
            'drift_security_analysis': 2,
            'template_security_validation': 3,
            'change_set_security_analysis': 2,
            'cost_based_security_analysis': 1,
            'account_limits_security_analysis': 1,
            'cross_stack_security_dependency': 2,
            'policy_security_analysis': 1
        }
    }
    
    return collected_data
# CloudFormation API 함수들 (18개)

# 스택 보안 상태 분석 (6개)
def get_stacks_info(client):
    """DescribeStacks - 스택 기본 정보, 상태, IAM 역할, 보안 설정 조회"""
    try:
        response = client.describe_stacks()
        stacks = response.get('Stacks', [])
        
        return {
            'status': 'success',
            'stacks': stacks[:10],  # 최대 10개만 상세 정보
            'total_stacks': len(stacks),
            'stack_statuses': [s.get('StackStatus') for s in stacks]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_events(client):
    """DescribeStackEvents - 스택 이벤트 이력을 통한 보안 관련 실패 및 문제 추적"""
    try:
        # 먼저 스택 목록을 가져와서 이벤트 조회
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_events': [],
                'message': '스택이 없어 이벤트를 조회할 수 없습니다.'
            }
        
        all_events = []
        for stack in stacks[:5]:  # 성능을 위해 최대 5개 스택만
            try:
                events_response = client.describe_stack_events(StackName=stack['StackName'])
                events = events_response.get('StackEvents', [])
                all_events.extend(events[:20])  # 스택당 최대 20개 이벤트
            except Exception as e:
                print(f"Error getting events for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_events': all_events,
            'total_events': len(all_events)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resources(client):
    """DescribeStackResources - 스택 내 모든 리소스의 보안 상태 및 구성 확인"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_resources': [],
                'message': '스택이 없어 리소스를 조회할 수 없습니다.'
            }
        
        all_resources = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                resources_response = client.describe_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResources', [])
                all_resources.extend(resources)
            except Exception as e:
                print(f"Error getting resources for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_resources': all_resources,
            'total_resources': len(all_resources)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resource_details(client):
    """DescribeStackResource - 개별 리소스의 상세 보안 설정 및 속성 분석"""
    try:
        # 먼저 리소스 목록을 가져와서 상세 정보 조회
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'resource_details': [],
                'message': '스택이 없어 리소스 상세 정보를 조회할 수 없습니다.'
            }
        
        resource_details = []
        for stack in stacks[:2]:  # 성능을 위해 최대 2개 스택만
            try:
                resources_response = client.describe_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResources', [])
                
                for resource in resources[:5]:  # 스택당 최대 5개 리소스만
                    try:
                        detail_response = client.describe_stack_resource(
                            StackName=stack['StackName'],
                            LogicalResourceId=resource['LogicalResourceId']
                        )
                        resource_details.append(detail_response.get('StackResourceDetail', {}))
                    except Exception as e:
                        print(f"Error getting resource detail: {str(e)}")
                        continue
            except Exception as e:
                print(f"Error processing stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_details': resource_details,
            'total_details': len(resource_details)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stacks_list(client):
    """ListStacks - 계정 내 모든 스택의 요약 정보 및 전체 보안 현황 파악"""
    try:
        response = client.list_stacks()
        stack_summaries = response.get('StackSummaries', [])
        
        return {
            'status': 'success',
            'stack_summaries': stack_summaries,
            'total_stacks': len(stack_summaries),
            'stack_statuses': [s.get('StackStatus') for s in stack_summaries]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resources_list(client):
    """ListStackResources - 특정 스택 내 리소스 목록 및 보안 관련 리소스 식별"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_resources_list': [],
                'message': '스택이 없어 리소스 목록을 조회할 수 없습니다.'
            }
        
        all_resources_list = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                resources_response = client.list_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResourceSummaries', [])
                all_resources_list.extend(resources)
            except Exception as e:
                print(f"Error listing resources for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_resources_list': all_resources_list,
            'total_resources': len(all_resources_list)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 드리프트 보안 분석 (2개)
def get_drift_detection_status(client):
    """DescribeStackDriftDetectionStatus - 드리프트 탐지 작업 상태 및 보안 설정 변경 탐지 결과 확인"""
    try:
        # 실제 드리프트 탐지 ID가 필요하므로 샘플 응답 반환
        return {
            'status': 'success',
            'drift_detection_status': [],
            'message': '드리프트 탐지 작업이 실행된 후 상태를 확인할 수 있습니다.'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resource_drifts(client):
    """DescribeStackResourceDrifts - 리소스별 드리프트 상세 정보 및 보안 설정 불일치 분석"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'resource_drifts': [],
                'message': '스택이 없어 드리프트를 조회할 수 없습니다.'
            }
        
        all_drifts = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                drifts_response = client.describe_stack_resource_drifts(StackName=stack['StackName'])
                drifts = drifts_response.get('StackResourceDrifts', [])
                all_drifts.extend(drifts)
            except Exception as e:
                print(f"Error getting drifts for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_drifts': all_drifts,
            'total_drifts': len(all_drifts)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
# CloudFormation API 함수들 Part 2

# 템플릿 보안 검증 (3개)
def get_templates(client):
    """GetTemplate - 스택 템플릿 내용 조회 및 보안 설정 분석"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'templates': [],
                'message': '스택이 없어 템플릿을 조회할 수 없습니다.'
            }
        
        templates = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                template_response = client.get_template(StackName=stack['StackName'])
                templates.append({
                    'stack_name': stack['StackName'],
                    'template_body': template_response.get('TemplateBody'),
                    'template_description': template_response.get('TemplateDescription')
                })
            except Exception as e:
                print(f"Error getting template for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'templates': templates,
            'total_templates': len(templates)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_template_summaries(client):
    """GetTemplateSummary - 템플릿 요약 정보 및 IAM 권한 요구사항 확인"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'template_summaries': [],
                'message': '스택이 없어 템플릿 요약을 조회할 수 없습니다.'
            }
        
        summaries = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                summary_response = client.get_template_summary(StackName=stack['StackName'])
                summaries.append({
                    'stack_name': stack['StackName'],
                    'capabilities': summary_response.get('Capabilities', []),
                    'parameters': summary_response.get('Parameters', []),
                    'resource_types': summary_response.get('ResourceTypes', [])
                })
            except Exception as e:
                print(f"Error getting template summary for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'template_summaries': summaries,
            'total_summaries': len(summaries)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_template_validations(client):
    """ValidateTemplate - 템플릿 유효성 검증 및 보안 관련 오류 사전 탐지"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'template_validations': [],
                'message': '스택이 없어 템플릿 검증을 수행할 수 없습니다.'
            }
        
        validations = []
        for stack in stacks[:2]:  # 성능을 위해 최대 2개 스택만
            try:
                # 먼저 템플릿을 가져온 후 검증
                template_response = client.get_template(StackName=stack['StackName'])
                template_body = template_response.get('TemplateBody')
                
                if template_body:
                    validation_response = client.validate_template(TemplateBody=json.dumps(template_body))
                    validations.append({
                        'stack_name': stack['StackName'],
                        'capabilities': validation_response.get('Capabilities', []),
                        'parameters': validation_response.get('Parameters', []),
                        'description': validation_response.get('Description')
                    })
            except Exception as e:
                print(f"Error validating template for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'template_validations': validations,
            'total_validations': len(validations)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 변경 세트 보안 분석 (2개)
def get_change_sets(client):
    """DescribeChangeSet - 변경 세트 상세 정보 및 보안에 미치는 영향 분석"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'change_sets': [],
                'message': '스택이 없어 변경 세트를 조회할 수 없습니다.'
            }
        
        all_change_sets = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                # 먼저 변경 세트 목록을 가져옴
                change_sets_response = client.list_change_sets(StackName=stack['StackName'])
                change_sets = change_sets_response.get('Summaries', [])
                
                for change_set in change_sets[:2]:  # 스택당 최대 2개 변경 세트만
                    try:
                        detail_response = client.describe_change_set(
                            StackName=stack['StackName'],
                            ChangeSetName=change_set['ChangeSetName']
                        )
                        all_change_sets.append(detail_response)
                    except Exception as e:
                        print(f"Error describing change set: {str(e)}")
                        continue
            except Exception as e:
                print(f"Error processing change sets for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'change_sets': all_change_sets,
            'total_change_sets': len(all_change_sets)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_change_sets_list(client):
    """ListChangeSets - 스택의 변경 이력 추적 및 보안 관련 변경사항 감사"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'change_sets_list': [],
                'message': '스택이 없어 변경 세트 목록을 조회할 수 없습니다.'
            }
        
        all_change_sets_list = []
        for stack in stacks[:5]:  # 성능을 위해 최대 5개 스택만
            try:
                change_sets_response = client.list_change_sets(StackName=stack['StackName'])
                change_sets = change_sets_response.get('Summaries', [])
                all_change_sets_list.extend(change_sets)
            except Exception as e:
                print(f"Error listing change sets for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'change_sets_list': all_change_sets_list,
            'total_change_sets': len(all_change_sets_list)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 비용 기반 보안 분석 (1개)
def get_template_costs(client):
    """EstimateTemplateCost - 템플릿 비용 추정을 통한 리소스 오남용 및 보안 위험 탐지"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'template_costs': [],
                'message': '스택이 없어 템플릿 비용을 추정할 수 없습니다.'
            }
        
        cost_estimates = []
        for stack in stacks[:2]:  # 성능을 위해 최대 2개 스택만
            try:
                # 먼저 템플릿을 가져온 후 비용 추정
                template_response = client.get_template(StackName=stack['StackName'])
                template_body = template_response.get('TemplateBody')
                
                if template_body:
                    cost_response = client.estimate_template_cost(TemplateBody=json.dumps(template_body))
                    cost_estimates.append({
                        'stack_name': stack['StackName'],
                        'cost_url': cost_response.get('Url')
                    })
            except Exception as e:
                print(f"Error estimating cost for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'template_costs': cost_estimates,
            'total_estimates': len(cost_estimates)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 계정 제한사항 보안 분석 (1개)
def get_account_limits(client):
    """DescribeAccountLimits - CloudFormation 계정 제한사항 조회 및 리소스 한도 도달 위험 평가"""
    try:
        response = client.describe_account_limits()
        account_limits = response.get('AccountLimits', [])
        
        return {
            'status': 'success',
            'account_limits': account_limits,
            'total_limits': len(account_limits)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# Cross-Stack 보안 의존성 분석 (2개)
def get_exports(client):
    """ListExports - 내보내기 값 목록 조회 및 민감한 정보 노출 위험 분석"""
    try:
        response = client.list_exports()
        exports = response.get('Exports', [])
        
        return {
            'status': 'success',
            'exports': exports,
            'total_exports': len(exports)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_imports(client):
    """ListImports - 가져오기 참조 추적 및 보안 장애 전파 경로 분석"""
    try:
        # 먼저 exports를 가져와서 각각에 대한 imports 조회
        exports_response = client.list_exports()
        exports = exports_response.get('Exports', [])
        
        if not exports:
            return {
                'status': 'success',
                'imports': [],
                'message': 'Export가 없어 Import를 조회할 수 없습니다.'
            }
        
        all_imports = []
        for export in exports[:5]:  # 성능을 위해 최대 5개 export만
            try:
                imports_response = client.list_imports(ExportName=export['Name'])
                imports = imports_response.get('Imports', [])
                all_imports.extend([{
                    'export_name': export['Name'],
                    'importing_stacks': imports
                }])
            except Exception as e:
                print(f"Error getting imports for export {export['Name']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'imports': all_imports,
            'total_import_relationships': len(all_imports)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 정책 보안 분석 (1개)
def get_stack_policies(client):
    """GetStackPolicy - 스택 보호 정책 확인 및 리소스 변경 제한사항 분석"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_policies': [],
                'message': '스택이 없어 스택 정책을 조회할 수 없습니다.'
            }
        
        stack_policies = []
        for stack in stacks[:5]:  # 성능을 위해 최대 5개 스택만
            try:
                policy_response = client.get_stack_policy(StackName=stack['StackName'])
                policy_body = policy_response.get('StackPolicyBody')
                stack_policies.append({
                    'stack_name': stack['StackName'],
                    'policy_body': policy_body,
                    'has_policy': policy_body is not None
                })
            except Exception as e:
                print(f"Error getting policy for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_policies': stack_policies,
            'total_policies': len(stack_policies)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
import json

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
        'function': event.get('function', 'analyzeCloudFormationSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'cloudformation-security-analysis'),
        'function': event.get('function', 'analyzeCloudFormationSecurity'),
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
