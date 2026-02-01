import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-01 Security Hub 보안 분석 Lambda 함수
    Security Hub의 모든 보안 상태 통합 대시보드 정보를 종합 분석
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
        
        securityhub_client = session.client('securityhub', region_name=target_region)
        
        # Security Hub 원시 데이터 수집
        raw_data = collect_securityhub_raw_data_parallel(securityhub_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeSecurityHubSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Security Hub 분석 중 오류 발생: {str(e)}"
        print(f"Error in Security Hub lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_securityhub_raw_data_parallel(client, target_region):
    """
    Security Hub 원시 데이터를 병렬로 수집 (21개 API)
    """
    # 먼저 Hub 활성화 상태 확인
    try:
        hub_response = client.describe_hub()
        hub_enabled = True
        hub_arn = hub_response.get('HubArn', '')
    except client.exceptions.InvalidAccessException:
        return {
            'function': 'analyzeSecurityHubSecurity',
            'target_region': target_region,
            'status': 'not_enabled',
            'message': 'Security Hub가 활성화되지 않았습니다.',
            'collection_summary': {
                'hub_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    except Exception as e:
        return {
            'function': 'analyzeSecurityHubSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'Security Hub 상태 확인 중 오류: {str(e)}',
            'collection_summary': {
                'hub_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의 (21개 API)
    collection_tasks = [
        # 1. 기본 설정 조회 (2개)
        ('hub_details', lambda: get_hub_details(client)),
        ('hub_v2_details', lambda: get_hub_v2_details(client)),
        
        # 2. 보안 표준 및 컨트롤 조회 (8개)
        ('standards', lambda: get_standards_data(client)),
        ('enabled_standards', lambda: get_enabled_standards_data(client)),
        ('standards_controls', lambda: get_standards_controls_data(client)),
        ('security_controls', lambda: get_security_controls_data(client)),
        ('control_definitions', lambda: get_control_definitions_data(client)),
        ('control_associations', lambda: get_control_associations_data(client)),
        ('batch_security_controls', lambda: get_batch_security_controls_data(client)),
        ('batch_control_associations', lambda: get_batch_control_associations_data(client)),
        
        # 3. 보안 발견사항 조회 (4개)
        ('findings', lambda: get_findings_data(client)),
        ('findings_v2', lambda: get_findings_v2_data(client)),
        ('findings_history', lambda: get_findings_history_data(client)),
        ('findings_statistics', lambda: get_findings_statistics_data(client)),
        
        # 4. 리소스 보안 상태 조회 (2개)
        ('resources', lambda: get_resources_data(client)),
        ('resources_statistics', lambda: get_resources_statistics_data(client)),
        
        # 5. 보안 제품 조회 (3개)
        ('products', lambda: get_products_data(client)),
        ('products_v2', lambda: get_products_v2_data(client)),
        ('enabled_products', lambda: get_enabled_products_data(client)),
        
        # 6. 크로스 리전 집계 조회 (2개)
        ('finding_aggregator', lambda: get_finding_aggregator_data(client)),
        ('finding_aggregators_list', lambda: get_finding_aggregators_list_data(client))
    ]
    
    # 병렬 처리 실행
    results = process_securityhub_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'hub_enabled': hub_enabled,
        'hub_arn': hub_arn,
        'data_categories_collected': len([k for k, v in results.items() if v is not None and v.get('status') != 'error']),
        'total_apis_called': 21,
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeSecurityHubSecurity',
        'target_region': target_region,
        'hub_arn': hub_arn,
        'securityhub_data': results,
        'collection_summary': collection_summary
    }

def process_securityhub_parallel(tasks, max_workers=5):
    """
    Security Hub 데이터 수집 작업을 병렬로 처리
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

# 1. 기본 설정 조회 (2개)
def get_hub_details(client):
    """DescribeHub - Security Hub 기본 설정 및 활성화 상태 조회"""
    try:
        response = client.describe_hub()
        return {
            'status': 'success',
            'hub_arn': response.get('HubArn', ''),
            'subscribed_at': response.get('SubscribedAt', ''),
            'auto_enable_controls': response.get('AutoEnableControls', False),
            'control_finding_generator': response.get('ControlFindingGenerator', '')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_hub_v2_details(client):
    """DescribeSecurityHubV2 - Security Hub V2 서비스 상세 정보 조회"""
    try:
        response = client.describe_security_hub_v2()
        return {
            'status': 'success',
            'hub_v2_arn': response.get('HubV2Arn', ''),
            'service_activated_at': response.get('ServiceActivatedAt', '')
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 2. 보안 표준 및 컨트롤 조회 (8개)
def get_standards_data(client):
    """DescribeStandards - 사용 가능한 보안 표준 목록 조회"""
    try:
        response = client.describe_standards()
        standards = response.get('Standards', [])
        return {
            'status': 'success',
            'total_standards': len(standards),
            'standards': standards
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_enabled_standards_data(client):
    """GetEnabledStandards - 현재 활성화된 보안 표준 목록 조회"""
    try:
        response = client.get_enabled_standards()
        enabled_standards = response.get('StandardsSubscriptions', [])
        return {
            'status': 'success',
            'total_enabled_standards': len(enabled_standards),
            'enabled_standards': enabled_standards
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_standards_controls_data(client):
    """DescribeStandardsControls - 특정 보안 표준의 개별 컨트롤 상태 조회"""
    try:
        # 먼저 활성화된 표준들을 가져와서 각각의 컨트롤 조회
        enabled_standards_response = client.get_enabled_standards()
        enabled_standards = enabled_standards_response.get('StandardsSubscriptions', [])
        
        all_controls = []
        for standard in enabled_standards[:3]:  # 성능을 위해 최대 3개 표준만 조회
            try:
                controls_response = client.describe_standards_controls(
                    StandardsSubscriptionArn=standard['StandardsSubscriptionArn']
                )
                controls = controls_response.get('Controls', [])
                all_controls.extend(controls)
            except Exception as e:
                print(f"Error getting controls for standard {standard.get('StandardsArn', '')}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'total_controls': len(all_controls),
            'controls': all_controls
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_security_controls_data(client):
    """BatchGetSecurityControls - 여러 보안 컨트롤의 현재 상태 일괄 조회"""
    try:
        # 먼저 컨트롤 정의 목록을 가져와서 일부 컨트롤 상태 조회
        definitions_response = client.list_security_control_definitions()
        definitions = definitions_response.get('SecurityControlDefinitions', [])
        
        if not definitions:
            return {
                'status': 'success',
                'total_controls': 0,
                'controls': []
            }
        
        # 처음 10개 컨트롤의 상태만 조회 (성능 고려)
        control_ids = [def_item['Id'] for def_item in definitions[:10]]
        
        response = client.batch_get_security_controls(SecurityControlIds=control_ids)
        controls = response.get('SecurityControls', [])
        
        return {
            'status': 'success',
            'total_controls_checked': len(control_ids),
            'controls': controls
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_control_definitions_data(client):
    """ListSecurityControlDefinitions - 모든 보안 컨트롤 정의 목록 조회"""
    try:
        response = client.list_security_control_definitions()
        definitions = response.get('SecurityControlDefinitions', [])
        return {
            'status': 'success',
            'total_definitions': len(definitions),
            'definitions': definitions[:20]  # 처음 20개만 반환 (성능 고려)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_control_associations_data(client):
    """ListStandardsControlAssociations - 보안 컨트롤과 표준 간의 연관관계 조회"""
    try:
        # 첫 번째 컨트롤 ID를 가져와서 연관관계 조회
        definitions_response = client.list_security_control_definitions()
        definitions = definitions_response.get('SecurityControlDefinitions', [])
        
        if not definitions:
            return {
                'status': 'success',
                'associations': []
            }
        
        first_control_id = definitions[0]['Id']
        response = client.list_standards_control_associations(SecurityControlId=first_control_id)
        associations = response.get('StandardsControlAssociationSummaries', [])
        
        return {
            'status': 'success',
            'control_id': first_control_id,
            'total_associations': len(associations),
            'associations': associations
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_batch_security_controls_data(client):
    """GetSecurityControlDefinition - 개별 보안 컨트롤의 상세 정의 조회"""
    try:
        # 첫 번째 컨트롤의 상세 정의 조회
        definitions_response = client.list_security_control_definitions()
        definitions = definitions_response.get('SecurityControlDefinitions', [])
        
        if not definitions:
            return {
                'status': 'success',
                'control_definition': None
            }
        
        first_control_id = definitions[0]['Id']
        response = client.get_security_control_definition(SecurityControlId=first_control_id)
        
        return {
            'status': 'success',
            'control_id': first_control_id,
            'control_definition': response.get('SecurityControlDefinition', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_batch_control_associations_data(client):
    """BatchGetStandardsControlAssociations - 보안 컨트롤과 표준 간의 연관관계 일괄 조회"""
    try:
        # 활성화된 표준과 컨트롤 정보를 가져와서 연관관계 조회
        enabled_standards_response = client.get_enabled_standards()
        enabled_standards = enabled_standards_response.get('StandardsSubscriptions', [])
        
        definitions_response = client.list_security_control_definitions()
        definitions = definitions_response.get('SecurityControlDefinitions', [])
        
        if not enabled_standards or not definitions:
            return {
                'status': 'success',
                'associations': []
            }
        
        # 첫 번째 표준과 첫 번째 컨트롤의 연관관계 조회
        requests = [{
            'SecurityControlId': definitions[0]['Id'],
            'StandardsArn': enabled_standards[0]['StandardsArn']
        }]
        
        response = client.batch_get_standards_control_associations(
            StandardsControlAssociationRequests=requests
        )
        
        return {
            'status': 'success',
            'associations': response.get('StandardsControlAssociationDetails', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 3. 보안 발견사항 조회 (4개)
def get_findings_data(client):
    """GetFindings - 보안 발견사항 상세 목록 조회"""
    try:
        response = client.get_findings(MaxResults=50)  # 최대 50개만 조회
        findings = response.get('Findings', [])
        return {
            'status': 'success',
            'total_findings': len(findings),
            'findings': findings
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_findings_v2_data(client):
    """GetFindingsV2 - OCSF 형식의 보안 발견사항 조회"""
    try:
        response = client.get_findings_v2(MaxResults=50)  # 최대 50개만 조회
        findings = response.get('Findings', [])
        return {
            'status': 'success',
            'total_findings_v2': len(findings),
            'findings_v2': findings
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_findings_history_data(client):
    """GetFindingHistory - 특정 보안 발견사항의 변경 이력 조회"""
    try:
        # 먼저 발견사항을 가져와서 첫 번째 발견사항의 이력 조회
        findings_response = client.get_findings(MaxResults=1)
        findings = findings_response.get('Findings', [])
        
        if not findings:
            return {
                'status': 'success',
                'finding_history': []
            }
        
        finding_id = findings[0]['Id']
        response = client.get_finding_history(FindingIdentifier={'Id': finding_id})
        
        return {
            'status': 'success',
            'finding_id': finding_id,
            'history_records': response.get('Records', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_findings_statistics_data(client):
    """GetFindingStatisticsV2 - 보안 발견사항 통계 데이터 조회"""
    try:
        response = client.get_finding_statistics_v2(
            GroupBy=['SeverityLabel']  # 심각도별 통계
        )
        return {
            'status': 'success',
            'statistics': response.get('Statistics', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 4. 리소스 보안 상태 조회 (2개)
def get_resources_data(client):
    """GetResourcesV2 - AWS 리소스 목록과 관련 보안 발견사항 요약 조회"""
    try:
        response = client.get_resources_v2(MaxResults=50)  # 최대 50개만 조회
        resources = response.get('Resources', [])
        return {
            'status': 'success',
            'total_resources': len(resources),
            'resources': resources
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resources_statistics_data(client):
    """GetResourcesStatisticsV2 - AWS 리소스 보안 발견사항 통계 정보 조회"""
    try:
        response = client.get_resources_statistics_v2(
            GroupBy=['ResourceType']  # 리소스 타입별 통계
        )
        return {
            'status': 'success',
            'statistics': response.get('Statistics', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 5. 보안 제품 조회 (3개)
def get_products_data(client):
    """DescribeProducts - Security Hub와 통합된 보안 제품 정보 조회"""
    try:
        response = client.describe_products()
        products = response.get('Products', [])
        return {
            'status': 'success',
            'total_products': len(products),
            'products': products
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_products_v2_data(client):
    """DescribeProductsV2 - 보안 제품 통합 정보 조회 개선 버전"""
    try:
        response = client.describe_products_v2()
        products = response.get('Products', [])
        return {
            'status': 'success',
            'total_products_v2': len(products),
            'products_v2': products
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_enabled_products_data(client):
    """ListEnabledProductsForImport - 현재 구독된 제품 목록 조회"""
    try:
        response = client.list_enabled_products_for_import()
        product_arns = response.get('ProductSubscriptions', [])
        return {
            'status': 'success',
            'total_enabled_products': len(product_arns),
            'enabled_products': product_arns
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 6. 크로스 리전 집계 조회 (2개)
def get_finding_aggregator_data(client):
    """GetFindingAggregator - 크로스 리전 집계 설정 상세 조회"""
    try:
        # 먼저 집계기 목록을 가져와서 첫 번째 집계기 상세 조회
        aggregators_response = client.list_finding_aggregators()
        aggregators = aggregators_response.get('FindingAggregators', [])
        
        if not aggregators:
            return {
                'status': 'success',
                'aggregator_details': None,
                'message': 'No finding aggregators configured'
            }
        
        first_aggregator_arn = aggregators[0]['FindingAggregatorArn']
        response = client.get_finding_aggregator(FindingAggregatorArn=first_aggregator_arn)
        
        return {
            'status': 'success',
            'aggregator_arn': first_aggregator_arn,
            'aggregator_details': response
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_finding_aggregators_list_data(client):
    """ListFindingAggregators - 발견사항 집계기 목록 조회"""
    try:
        response = client.list_finding_aggregators()
        aggregators = response.get('FindingAggregators', [])
        return {
            'status': 'success',
            'total_aggregators': len(aggregators),
            'aggregators': aggregators
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
        'function': event.get('function', 'analyzeSecurityHubSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'security-hub-analysis'),
        'function': event.get('function', 'analyzeSecurityHubSecurity'),
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
