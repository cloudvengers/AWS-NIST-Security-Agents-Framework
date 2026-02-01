import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-01 Trusted Advisor 보안 분석 Lambda 함수
    Trusted Advisor의 모든 보안 모범 사례 권장사항을 종합 분석
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
        
        # Trusted Advisor는 us-east-1에서만 사용 가능
        if target_region != 'us-east-1':
            return create_bedrock_error_response(event, "Trusted Advisor는 us-east-1 리전에서만 사용 가능합니다.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name='us-east-1'  # Trusted Advisor는 항상 us-east-1
        )
        
        trustedadvisor_client = session.client('trustedadvisor', region_name='us-east-1')
        
        # Trusted Advisor 원시 데이터 수집
        raw_data = collect_trustedadvisor_raw_data_parallel(trustedadvisor_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeTrustedAdvisorSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Trusted Advisor 분석 중 오류 발생: {str(e)}"
        print(f"Error in Trusted Advisor lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_trustedadvisor_raw_data_parallel(client, target_region):
    """
    Trusted Advisor 원시 데이터를 병렬로 수집 (4개 API)
    """
    # 병렬 데이터 수집 작업 정의 (4개 API)
    collection_tasks = [
        ('checks', lambda: get_checks_data(client)),
        ('recommendations', lambda: get_recommendations_data(client)),
        ('recommendation_details', lambda: get_recommendation_details_data(client)),
        ('recommendation_resources', lambda: get_recommendation_resources_data(client))
    ]
    
    # 병렬 처리 실행
    results = process_trustedadvisor_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'data_categories_collected': len([k for k, v in results.items() if v is not None and v.get('status') != 'error']),
        'total_apis_called': 4,
        'collection_method': 'parallel_processing',
        'region': 'us-east-1',  # Trusted Advisor는 항상 us-east-1
        'note': 'Trusted Advisor requires Business or Enterprise support plan'
    }
    
    return {
        'function': 'analyzeTrustedAdvisorSecurity',
        'target_region': target_region,
        'trustedadvisor_data': results,
        'collection_summary': collection_summary
    }

def process_trustedadvisor_parallel(tasks, max_workers=4):
    """
    Trusted Advisor 데이터 수집 작업을 병렬로 처리
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

# Trusted Advisor API 함수들 (4개)
def get_checks_data(client):
    """ListChecks - 보안 체크 항목 파악"""
    try:
        # 보안 관련 체크만 필터링
        response = client.list_checks(
            pillar='security',
            language='en'
        )
        checks = response.get('checkSummaries', [])
        
        return {
            'status': 'success',
            'total_security_checks': len(checks),
            'security_checks': checks
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_recommendations_data(client):
    """ListRecommendations - 보안 권장사항 목록 확인"""
    try:
        # 보안 관련 권장사항만 필터링
        response = client.list_recommendations(
            pillar='security',
            maxResults=100  # 최대 100개 권장사항
        )
        recommendations = response.get('recommendationSummaries', [])
        
        return {
            'status': 'success',
            'total_security_recommendations': len(recommendations),
            'security_recommendations': recommendations
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_recommendation_details_data(client):
    """GetRecommendation - 개별 보안 권장사항 상세 분석"""
    try:
        # 먼저 권장사항 목록을 가져와서 첫 번째 권장사항의 상세 정보 조회
        recommendations_response = client.list_recommendations(
            pillar='security',
            maxResults=1
        )
        recommendations = recommendations_response.get('recommendationSummaries', [])
        
        if not recommendations:
            return {
                'status': 'success',
                'recommendation_detail': None,
                'message': 'No security recommendations found'
            }
        
        first_recommendation_id = recommendations[0]['id']
        response = client.get_recommendation(recommendationIdentifier=first_recommendation_id)
        
        return {
            'status': 'success',
            'recommendation_id': first_recommendation_id,
            'recommendation_detail': response.get('recommendation', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_recommendation_resources_data(client):
    """ListRecommendationResources - 보안 이슈가 있는 리소스 식별"""
    try:
        # 먼저 권장사항 목록을 가져와서 첫 번째 권장사항의 리소스 조회
        recommendations_response = client.list_recommendations(
            pillar='security',
            maxResults=1
        )
        recommendations = recommendations_response.get('recommendationSummaries', [])
        
        if not recommendations:
            return {
                'status': 'success',
                'recommendation_resources': [],
                'message': 'No security recommendations found for resource listing'
            }
        
        first_recommendation_id = recommendations[0]['id']
        response = client.list_recommendation_resources(
            recommendationIdentifier=first_recommendation_id,
            maxResults=50  # 최대 50개 리소스
        )
        
        return {
            'status': 'success',
            'recommendation_id': first_recommendation_id,
            'total_resources': len(response.get('recommendationResourceSummaries', [])),
            'recommendation_resources': response.get('recommendationResourceSummaries', [])
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
        'function': event.get('function', 'analyzeTrustedAdvisorSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'trusted-advisor-analysis'),
        'function': event.get('function', 'analyzeTrustedAdvisorSecurity'),
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
