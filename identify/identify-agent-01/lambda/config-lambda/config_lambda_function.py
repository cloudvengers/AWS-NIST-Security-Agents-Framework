import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-01 Config 보안 분석 Lambda 함수
    Config의 모든 구성 변경 추적 및 정책 준수 정보를 종합 분석
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
        
        config_client = session.client('config', region_name=target_region)
        
        # Config 원시 데이터 수집
        raw_data = collect_config_raw_data_parallel(config_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeConfigSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Config 분석 중 오류 발생: {str(e)}"
        print(f"Error in Config lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_config_raw_data_parallel(client, target_region):
    """
    Config 원시 데이터를 병렬로 수집 (32개 API)
    """
    # 먼저 Configuration Recorder 상태 확인
    try:
        recorders_response = client.describe_configuration_recorders()
        recorders = recorders_response.get('ConfigurationRecorders', [])
        config_enabled = len(recorders) > 0
    except Exception as e:
        return {
            'function': 'analyzeConfigSecurity',
            'target_region': target_region,
            'status': 'error',
            'message': f'Config 상태 확인 중 오류: {str(e)}',
            'collection_summary': {
                'config_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not config_enabled:
        return {
            'function': 'analyzeConfigSecurity',
            'target_region': target_region,
            'status': 'not_enabled',
            'message': 'AWS Config가 활성화되지 않았습니다.',
            'collection_summary': {
                'config_enabled': False,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의 (32개 API)
    collection_tasks = [
        # 1. 규정 준수 상태 조회 (6개)
        ('compliance_by_config_rule', lambda: get_compliance_by_config_rule(client)),
        ('compliance_by_resource', lambda: get_compliance_by_resource(client)),
        ('compliance_details_by_config_rule', lambda: get_compliance_details_by_config_rule(client)),
        ('compliance_details_by_resource', lambda: get_compliance_details_by_resource(client)),
        ('compliance_summary_by_config_rule', lambda: get_compliance_summary_by_config_rule(client)),
        ('compliance_summary_by_resource_type', lambda: get_compliance_summary_by_resource_type(client)),
        
        # 2. 리소스 구성 조회 (5개)
        ('batch_resource_config', lambda: get_batch_resource_config(client)),
        ('discovered_resources', lambda: get_discovered_resources(client)),
        ('discovered_resource_counts', lambda: get_discovered_resource_counts(client)),
        ('resource_config_history', lambda: get_resource_config_history(client)),
        ('select_resource_config', lambda: get_select_resource_config(client)),
        
        # 3. Config 규칙 및 평가 (4개)
        ('config_rules', lambda: get_config_rules(client)),
        ('config_rule_evaluation_status', lambda: get_config_rule_evaluation_status(client)),
        ('resource_evaluations', lambda: get_resource_evaluations(client)),
        ('resource_evaluation_summary', lambda: get_resource_evaluation_summary(client)),
        
        # 4. 적합성 팩 (6개)
        ('conformance_packs', lambda: get_conformance_packs(client)),
        ('conformance_pack_status', lambda: get_conformance_pack_status(client)),
        ('conformance_pack_compliance', lambda: get_conformance_pack_compliance(client)),
        ('conformance_pack_compliance_details', lambda: get_conformance_pack_compliance_details(client)),
        ('conformance_pack_compliance_summary', lambda: get_conformance_pack_compliance_summary(client)),
        ('conformance_pack_compliance_scores', lambda: get_conformance_pack_compliance_scores(client)),
        
        # 5. Config 서비스 상태 (5개)
        ('configuration_recorders', lambda: get_configuration_recorders(client)),
        ('configuration_recorder_status', lambda: get_configuration_recorder_status(client)),
        ('configuration_recorders_list', lambda: get_configuration_recorders_list(client)),
        ('delivery_channels', lambda: get_delivery_channels(client)),
        ('delivery_channel_status', lambda: get_delivery_channel_status(client)),
        
        # 6. 저장된 쿼리 (2개)
        ('stored_query', lambda: get_stored_query(client)),
        ('stored_queries_list', lambda: get_stored_queries_list(client)),
        
        # 7. 수정 관련 조회 (3개)
        ('remediation_configurations', lambda: get_remediation_configurations(client)),
        ('remediation_exceptions', lambda: get_remediation_exceptions(client)),
        ('remediation_execution_status', lambda: get_remediation_execution_status(client)),
        
        # 8. 데이터 보존 및 정책 (2개)
        ('retention_configurations', lambda: get_retention_configurations(client)),
        ('custom_rule_policy', lambda: get_custom_rule_policy(client))
    ]
    
    # 병렬 처리 실행
    results = process_config_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'config_enabled': config_enabled,
        'configuration_recorders': len(recorders),
        'data_categories_collected': len([k for k, v in results.items() if v is not None and v.get('status') != 'error']),
        'total_apis_called': 32,
        'collection_method': 'parallel_processing',
        'region': target_region
    }
    
    return {
        'function': 'analyzeConfigSecurity',
        'target_region': target_region,
        'configuration_recorders': recorders,
        'config_data': results,
        'collection_summary': collection_summary
    }

def process_config_parallel(tasks, max_workers=5):
    """
    Config 데이터 수집 작업을 병렬로 처리
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

# 1. 규정 준수 상태 조회 (6개)
def get_compliance_by_config_rule(client):
    """DescribeComplianceByConfigRule - Config 규칙별 규정 준수 상태 조회"""
    try:
        response = client.describe_compliance_by_config_rule()
        compliance_data = response.get('ComplianceByConfigRules', [])
        return {
            'status': 'success',
            'total_rules': len(compliance_data),
            'compliance_by_rules': compliance_data
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_by_resource(client):
    """DescribeComplianceByResource - 리소스별 규정 준수 상태 조회"""
    try:
        response = client.describe_compliance_by_resource()
        compliance_data = response.get('ComplianceByResources', [])
        return {
            'status': 'success',
            'total_resources': len(compliance_data),
            'compliance_by_resources': compliance_data[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_details_by_config_rule(client):
    """GetComplianceDetailsByConfigRule - Config 규칙의 상세 규정 준수 정보"""
    try:
        # 먼저 규칙 목록을 가져와서 첫 번째 규칙의 상세 정보 조회
        rules_response = client.describe_config_rules()
        rules = rules_response.get('ConfigRules', [])
        
        if not rules:
            return {
                'status': 'success',
                'compliance_details': [],
                'message': 'No Config rules found'
            }
        
        first_rule_name = rules[0]['ConfigRuleName']
        response = client.get_compliance_details_by_config_rule(ConfigRuleName=first_rule_name)
        
        return {
            'status': 'success',
            'config_rule_name': first_rule_name,
            'evaluation_results': response.get('EvaluationResults', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_details_by_resource(client):
    """GetComplianceDetailsByResource - 리소스의 상세 규정 준수 정보"""
    try:
        # 먼저 리소스 목록을 가져와서 첫 번째 리소스의 상세 정보 조회
        resources_response = client.list_discovered_resources(resourceType='AWS::S3::Bucket')
        resources = resources_response.get('resourceIdentifiers', [])
        
        if not resources:
            return {
                'status': 'success',
                'compliance_details': [],
                'message': 'No resources found for compliance check'
            }
        
        first_resource = resources[0]
        response = client.get_compliance_details_by_resource(
            ResourceType=first_resource['resourceType'],
            ResourceId=first_resource['resourceId']
        )
        
        return {
            'status': 'success',
            'resource_type': first_resource['resourceType'],
            'resource_id': first_resource['resourceId'],
            'evaluation_results': response.get('EvaluationResults', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_summary_by_config_rule(client):
    """GetComplianceSummaryByConfigRule - Config 규칙별 규정 준수 요약 통계"""
    try:
        response = client.get_compliance_summary_by_config_rule()
        return {
            'status': 'success',
            'compliance_summary': response.get('ComplianceSummary', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_compliance_summary_by_resource_type(client):
    """GetComplianceSummaryByResourceType - 리소스 유형별 규정 준수 요약 통계"""
    try:
        response = client.get_compliance_summary_by_resource_type()
        return {
            'status': 'success',
            'compliance_summaries': response.get('ComplianceSummariesByResourceType', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 2. 리소스 구성 조회 (5개)
def get_batch_resource_config(client):
    """BatchGetResourceConfig - 여러 리소스의 현재 구성 정보 일괄 조회"""
    try:
        # 먼저 리소스 목록을 가져와서 일부 리소스의 구성 정보 조회
        resources_response = client.list_discovered_resources(resourceType='AWS::S3::Bucket')
        resources = resources_response.get('resourceIdentifiers', [])
        
        if not resources:
            return {
                'status': 'success',
                'resource_configs': [],
                'message': 'No resources found for batch config retrieval'
            }
        
        # 처음 5개 리소스만 조회 (성능 고려)
        resource_keys = [
            {
                'resourceType': res['resourceType'],
                'resourceId': res['resourceId']
            }
            for res in resources[:5]
        ]
        
        response = client.batch_get_resource_config(resourceKeys=resource_keys)
        
        return {
            'status': 'success',
            'total_requested': len(resource_keys),
            'base_configuration_items': response.get('baseConfigurationItems', []),
            'unprocessed_resource_keys': response.get('unprocessedResourceKeys', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_discovered_resources(client):
    """ListDiscoveredResources - AWS Config가 발견한 리소스 목록 조회"""
    try:
        # 여러 리소스 타입에 대해 조회
        resource_types = ['AWS::S3::Bucket', 'AWS::EC2::Instance', 'AWS::IAM::Role']
        all_resources = []
        
        for resource_type in resource_types:
            try:
                response = client.list_discovered_resources(resourceType=resource_type)
                resources = response.get('resourceIdentifiers', [])
                all_resources.extend([{
                    'resource_type': resource_type,
                    'resources': resources[:10]  # 각 타입별로 최대 10개만
                }])
            except Exception as e:
                print(f"Error getting resources for {resource_type}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_types_checked': len(resource_types),
            'discovered_resources': all_resources
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_discovered_resource_counts(client):
    """GetDiscoveredResourceCounts - 발견된 리소스의 유형별 개수 통계"""
    try:
        response = client.get_discovered_resource_counts()
        return {
            'status': 'success',
            'total_discovered_resources': response.get('totalDiscoveredResources', 0),
            'resource_counts': response.get('resourceCounts', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resource_config_history(client):
    """GetResourceConfigHistory - 리소스 구성 변경 이력 및 시간별 추적"""
    try:
        # 먼저 리소스를 가져와서 첫 번째 리소스의 구성 이력 조회
        resources_response = client.list_discovered_resources(resourceType='AWS::S3::Bucket')
        resources = resources_response.get('resourceIdentifiers', [])
        
        if not resources:
            return {
                'status': 'success',
                'config_history': [],
                'message': 'No resources found for config history'
            }
        
        first_resource = resources[0]
        response = client.get_resource_config_history(
            resourceType=first_resource['resourceType'],
            resourceId=first_resource['resourceId']
        )
        
        return {
            'status': 'success',
            'resource_type': first_resource['resourceType'],
            'resource_id': first_resource['resourceId'],
            'configuration_items': response.get('configurationItems', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_select_resource_config(client):
    """SelectResourceConfig - SQL 쿼리를 통한 리소스 구성 검색"""
    try:
        # 간단한 SQL 쿼리로 S3 버킷 조회
        expression = "SELECT resourceId, resourceType WHERE resourceType = 'AWS::S3::Bucket'"
        response = client.select_resource_config(Expression=expression)
        
        return {
            'status': 'success',
            'query_expression': expression,
            'results': response.get('Results', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 3. Config 규칙 및 평가 (4개)
def get_config_rules(client):
    """DescribeConfigRules - 설정된 Config 규칙 목록 및 세부 정보"""
    try:
        response = client.describe_config_rules()
        rules = response.get('ConfigRules', [])
        return {
            'status': 'success',
            'total_rules': len(rules),
            'config_rules': rules
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_config_rule_evaluation_status(client):
    """DescribeConfigRuleEvaluationStatus - Config 규칙의 평가 상태 및 실행 이력"""
    try:
        response = client.describe_config_rule_evaluation_status()
        evaluation_statuses = response.get('ConfigRulesEvaluationStatus', [])
        return {
            'status': 'success',
            'total_evaluations': len(evaluation_statuses),
            'evaluation_statuses': evaluation_statuses
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resource_evaluations(client):
    """ListResourceEvaluations - 리소스 평가 목록 조회"""
    try:
        response = client.list_resource_evaluations()
        evaluations = response.get('ResourceEvaluations', [])
        return {
            'status': 'success',
            'total_evaluations': len(evaluations),
            'resource_evaluations': evaluations[:20]  # 처음 20개만 반환
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_resource_evaluation_summary(client):
    """GetResourceEvaluationSummary - 특정 리소스 평가의 요약 정보"""
    try:
        # 먼저 평가 목록을 가져와서 첫 번째 평가의 요약 조회
        evaluations_response = client.list_resource_evaluations()
        evaluations = evaluations_response.get('ResourceEvaluations', [])
        
        if not evaluations:
            return {
                'status': 'success',
                'evaluation_summary': None,
                'message': 'No resource evaluations found'
            }
        
        first_evaluation_id = evaluations[0]['ResourceEvaluationId']
        response = client.get_resource_evaluation_summary(ResourceEvaluationId=first_evaluation_id)
        
        return {
            'status': 'success',
            'resource_evaluation_id': first_evaluation_id,
            'evaluation_summary': response.get('ResourceEvaluationSummary', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 4. 적합성 팩 (6개)
def get_conformance_packs(client):
    """DescribeConformancePacks - 적용된 적합성 팩 정보"""
    try:
        response = client.describe_conformance_packs()
        conformance_packs = response.get('ConformancePackDetails', [])
        return {
            'status': 'success',
            'total_conformance_packs': len(conformance_packs),
            'conformance_packs': conformance_packs
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_conformance_pack_status(client):
    """DescribeConformancePackStatus - 적합성 팩의 배포 상태 및 오류 정보"""
    try:
        response = client.describe_conformance_pack_status()
        statuses = response.get('ConformancePackStatusDetails', [])
        return {
            'status': 'success',
            'total_statuses': len(statuses),
            'conformance_pack_statuses': statuses
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_conformance_pack_compliance(client):
    """DescribeConformancePackCompliance - 적합성 팩 내 규칙별 규정 준수 상태"""
    try:
        # 먼저 적합성 팩 목록을 가져와서 첫 번째 팩의 준수 상태 조회
        packs_response = client.describe_conformance_packs()
        packs = packs_response.get('ConformancePackDetails', [])
        
        if not packs:
            return {
                'status': 'success',
                'compliance_details': [],
                'message': 'No conformance packs found'
            }
        
        first_pack_name = packs[0]['ConformancePackName']
        response = client.describe_conformance_pack_compliance(ConformancePackName=first_pack_name)
        
        return {
            'status': 'success',
            'conformance_pack_name': first_pack_name,
            'compliance_details': response.get('ConformancePackRuleComplianceList', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_conformance_pack_compliance_details(client):
    """GetConformancePackComplianceDetails - 적합성 팩의 상세 규정 준수 정보"""
    try:
        # 먼저 적합성 팩 목록을 가져와서 첫 번째 팩의 상세 준수 정보 조회
        packs_response = client.describe_conformance_packs()
        packs = packs_response.get('ConformancePackDetails', [])
        
        if not packs:
            return {
                'status': 'success',
                'compliance_details': [],
                'message': 'No conformance packs found'
            }
        
        first_pack_name = packs[0]['ConformancePackName']
        response = client.get_conformance_pack_compliance_details(ConformancePackName=first_pack_name)
        
        return {
            'status': 'success',
            'conformance_pack_name': first_pack_name,
            'compliance_details': response.get('ConformancePackRuleEvaluationResults', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_conformance_pack_compliance_summary(client):
    """GetConformancePackComplianceSummary - 적합성 팩의 규정 준수 요약"""
    try:
        response = client.get_conformance_pack_compliance_summary()
        summaries = response.get('ConformancePackComplianceSummaryList', [])
        return {
            'status': 'success',
            'total_summaries': len(summaries),
            'compliance_summaries': summaries
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_conformance_pack_compliance_scores(client):
    """ListConformancePackComplianceScores - 적합성 팩의 준수 점수 및 성숙도 측정"""
    try:
        response = client.list_conformance_pack_compliance_scores()
        scores = response.get('ConformancePackComplianceScores', [])
        return {
            'status': 'success',
            'total_scores': len(scores),
            'compliance_scores': scores
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 5. Config 서비스 상태 (5개)
def get_configuration_recorders(client):
    """DescribeConfigurationRecorders - Configuration Recorder 설정 정보"""
    try:
        response = client.describe_configuration_recorders()
        recorders = response.get('ConfigurationRecorders', [])
        return {
            'status': 'success',
            'total_recorders': len(recorders),
            'configuration_recorders': recorders
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_configuration_recorder_status(client):
    """DescribeConfigurationRecorderStatus - Configuration Recorder 동작 상태 및 오류"""
    try:
        response = client.describe_configuration_recorder_status()
        statuses = response.get('ConfigurationRecordersStatus', [])
        return {
            'status': 'success',
            'total_statuses': len(statuses),
            'recorder_statuses': statuses
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_configuration_recorders_list(client):
    """ListConfigurationRecorders - Configuration Recorder 목록"""
    try:
        response = client.list_configuration_recorders()
        recorder_names = response.get('ConfigurationRecorderNames', [])
        return {
            'status': 'success',
            'total_recorder_names': len(recorder_names),
            'recorder_names': recorder_names
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_delivery_channels(client):
    """DescribeDeliveryChannels - Config 데이터 전송 채널 설정 정보"""
    try:
        response = client.describe_delivery_channels()
        channels = response.get('DeliveryChannels', [])
        return {
            'status': 'success',
            'total_channels': len(channels),
            'delivery_channels': channels
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_delivery_channel_status(client):
    """DescribeDeliveryChannelStatus - 데이터 전송 채널 상태 및 전송 이력"""
    try:
        response = client.describe_delivery_channel_status()
        statuses = response.get('DeliveryChannelsStatus', [])
        return {
            'status': 'success',
            'total_statuses': len(statuses),
            'channel_statuses': statuses
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 6. 저장된 쿼리 (2개)
def get_stored_query(client):
    """GetStoredQuery - 저장된 쿼리의 세부 정보 및 SQL 내용"""
    try:
        # 먼저 저장된 쿼리 목록을 가져와서 첫 번째 쿼리의 상세 정보 조회
        queries_response = client.list_stored_queries()
        queries = queries_response.get('StoredQueryMetadata', [])
        
        if not queries:
            return {
                'status': 'success',
                'stored_query': None,
                'message': 'No stored queries found'
            }
        
        first_query_name = queries[0]['QueryName']
        response = client.get_stored_query(QueryName=first_query_name)
        
        return {
            'status': 'success',
            'query_name': first_query_name,
            'stored_query': response.get('StoredQuery', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stored_queries_list(client):
    """ListStoredQueries - 저장된 쿼리 목록 및 메타데이터"""
    try:
        response = client.list_stored_queries()
        queries = response.get('StoredQueryMetadata', [])
        return {
            'status': 'success',
            'total_queries': len(queries),
            'stored_queries': queries
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 7. 수정 관련 조회 (3개)
def get_remediation_configurations(client):
    """DescribeRemediationConfigurations - 자동 수정 구성 정보"""
    try:
        # 먼저 Config 규칙을 가져와서 수정 구성 조회
        rules_response = client.describe_config_rules()
        rules = rules_response.get('ConfigRules', [])
        
        if not rules:
            return {
                'status': 'success',
                'remediation_configurations': [],
                'message': 'No Config rules found for remediation check'
            }
        
        rule_names = [rule['ConfigRuleName'] for rule in rules[:5]]  # 처음 5개만
        response = client.describe_remediation_configurations(ConfigRuleNames=rule_names)
        
        return {
            'status': 'success',
            'total_configurations': len(response.get('RemediationConfigurations', [])),
            'remediation_configurations': response.get('RemediationConfigurations', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_remediation_exceptions(client):
    """DescribeRemediationExceptions - 자동 수정에서 제외된 리소스 및 예외 사항"""
    try:
        # 먼저 Config 규칙을 가져와서 수정 예외 조회
        rules_response = client.describe_config_rules()
        rules = rules_response.get('ConfigRules', [])
        
        if not rules:
            return {
                'status': 'success',
                'remediation_exceptions': [],
                'message': 'No Config rules found for remediation exceptions check'
            }
        
        first_rule_name = rules[0]['ConfigRuleName']
        response = client.describe_remediation_exceptions(ConfigRuleName=first_rule_name)
        
        return {
            'status': 'success',
            'config_rule_name': first_rule_name,
            'remediation_exceptions': response.get('RemediationExceptions', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_remediation_execution_status(client):
    """DescribeRemediationExecutionStatus - 자동 수정 작업의 실행 상태 및 결과"""
    try:
        # 먼저 Config 규칙을 가져와서 수정 실행 상태 조회
        rules_response = client.describe_config_rules()
        rules = rules_response.get('ConfigRules', [])
        
        if not rules:
            return {
                'status': 'success',
                'execution_statuses': [],
                'message': 'No Config rules found for remediation execution status check'
            }
        
        first_rule_name = rules[0]['ConfigRuleName']
        response = client.describe_remediation_execution_status(ConfigRuleName=first_rule_name)
        
        return {
            'status': 'success',
            'config_rule_name': first_rule_name,
            'execution_statuses': response.get('RemediationExecutionStatuses', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 8. 데이터 보존 및 정책 (2개)
def get_retention_configurations(client):
    """DescribeRetentionConfigurations - Config 데이터 보존 정책 설정"""
    try:
        response = client.describe_retention_configurations()
        configurations = response.get('RetentionConfigurations', [])
        return {
            'status': 'success',
            'total_configurations': len(configurations),
            'retention_configurations': configurations
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_custom_rule_policy(client):
    """GetCustomRulePolicy - 사용자 정의 규칙의 정책 내용 및 로직"""
    try:
        # 먼저 사용자 정의 규칙을 찾아서 정책 조회
        rules_response = client.describe_config_rules()
        rules = rules_response.get('ConfigRules', [])
        
        custom_rules = [rule for rule in rules if rule.get('Source', {}).get('Owner') == 'CUSTOM_POLICY']
        
        if not custom_rules:
            return {
                'status': 'success',
                'custom_rule_policy': None,
                'message': 'No custom policy rules found'
            }
        
        first_custom_rule = custom_rules[0]['ConfigRuleName']
        response = client.get_custom_rule_policy(ConfigRuleName=first_custom_rule)
        
        return {
            'status': 'success',
            'config_rule_name': first_custom_rule,
            'policy_text': response.get('PolicyText', '')
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
        'function': event.get('function', 'analyzeConfigSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'config-analysis'),
        'function': event.get('function', 'analyzeConfigSecurity'),
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
