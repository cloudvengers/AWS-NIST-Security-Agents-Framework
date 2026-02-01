import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

def lambda_handler(event, context):
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region')
        
        if not target_region:
            return create_bedrock_error_response(event, "target_region parameter is required")
        
        # 세션 속성에서 고객 자격증명 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "Customer credentials not found in session")
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        stepfunctions_client = session.client('stepfunctions')
        
        # Step Functions 상세 보안 분석 (병렬 처리)
        analysis_data = analyze_stepfunctions_security_parallel(stepfunctions_client, current_time)
        
        # 수집 요약 정보 추가
        analysis_data['collection_summary'] = {
            'function': 'analyzeRespondAgent01StepFunctions',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'analysis_timestamp': context.aws_request_id,
            'apis_used': [
                'list_state_machines', 'describe_state_machine', 'validate_state_machine_definition',
                'list_activities', 'describe_activity',
                'list_executions', 'describe_execution', 'get_execution_history',
                'list_tags_for_resource'
            ],
            'total_state_machines_analyzed': len(analysis_data.get('state_machines', [])),
            'total_activities_analyzed': len(analysis_data.get('activities', [])),
            'total_executions_analyzed': sum(len(sm.get('recent_executions', [])) for sm in analysis_data.get('state_machines', []))
        }
        
        return create_bedrock_success_response(event, analysis_data)
        
    except Exception as e:
        print(f"Error in stepfunctions analysis lambda: {str(e)}")
        return create_bedrock_error_response(event, f"Step Functions analysis failed: {str(e)}")

def analyze_stepfunctions_security_parallel(client, current_time):
    """Step Functions 보안 분석을 병렬로 수행"""
    
    # 1단계: State Machine과 Activity 목록 조회
    state_machines = get_all_state_machines(client)
    activities = get_all_activities(client)
    
    results = {
        'function': 'analyzeRespondAgent01StepFunctions',
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'state_machines': [],
        'activities': [],
        'security_analysis_summary': {}
    }
    
    # 2단계: State Machine 상세 분석 (병렬 처리)
    if state_machines:
        results['state_machines'] = process_state_machines_parallel(client, state_machines)
    
    # 3단계: Activity 상세 분석 (병렬 처리)
    if activities:
        results['activities'] = process_activities_parallel(client, activities)
    
    # 4단계: 보안 분석 요약 생성
    results['security_analysis_summary'] = generate_security_summary(results)
    
    return results

def get_all_state_machines(client):
    """모든 State Machine 목록 조회"""
    try:
        response = client.list_state_machines()
        return response.get('stateMachines', [])
    except Exception as e:
        print(f"Error listing state machines: {str(e)}")
        return []

def get_all_activities(client):
    """모든 Activity 목록 조회"""
    try:
        response = client.list_activities()
        return response.get('activities', [])
    except Exception as e:
        print(f"Error listing activities: {str(e)}")
        return []

def process_state_machines_parallel(client, state_machines, max_workers=5):
    """State Machine들을 병렬로 처리"""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_state_machine, client, sm) for sm in state_machines]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing state machine: {str(e)}")
                continue
    
    return results

def analyze_single_state_machine(client, state_machine):
    """개별 State Machine 상세 분석"""
    try:
        state_machine_arn = state_machine['stateMachineArn']
        
        # State Machine 상세 정보 조회
        sm_details = client.describe_state_machine(stateMachineArn=state_machine_arn)
        
        # State Machine 정의 검증
        validation_result = validate_state_machine_definition(client, sm_details.get('definition', ''))
        
        # 최근 실행 이력 조회
        recent_executions = get_recent_executions(client, state_machine_arn)
        
        # 태그 정보 조회
        tags = get_resource_tags(client, state_machine_arn)
        
        return {
            'name': state_machine.get('name'),
            'arn': state_machine_arn,
            'type': state_machine.get('type'),
            'status': sm_details.get('status'),
            'creation_date': sm_details.get('creationDate'),
            'definition': sm_details.get('definition'),
            'role_arn': sm_details.get('roleArn'),
            'validation_result': validation_result,
            'recent_executions': recent_executions,
            'tags': tags,
            'security_assessment': assess_state_machine_security(sm_details, recent_executions, tags)
        }
        
    except Exception as e:
        print(f"Error analyzing state machine {state_machine.get('name', 'Unknown')}: {str(e)}")
        return {
            'name': state_machine.get('name', 'Unknown'),
            'arn': state_machine.get('stateMachineArn', 'Unknown'),
            'error': str(e)
        }

def validate_state_machine_definition(client, definition):
    """State Machine 정의 검증"""
    try:
        if not definition:
            return {'valid': False, 'error': 'No definition provided'}
            
        response = client.validate_state_machine_definition(definition=definition)
        return {
            'valid': response.get('result') == 'OK',
            'diagnostics': response.get('diagnostics', [])
        }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def get_recent_executions(client, state_machine_arn, max_results=10):
    """최근 실행 이력 조회"""
    try:
        response = client.list_executions(
            stateMachineArn=state_machine_arn,
            maxResults=max_results
        )
        
        executions = []
        for execution in response.get('executions', []):
            exec_details = get_execution_details(client, execution['executionArn'])
            executions.append(exec_details)
        
        return executions
        
    except Exception as e:
        print(f"Error getting recent executions: {str(e)}")
        return []

def get_execution_details(client, execution_arn):
    """개별 실행 상세 정보 조회"""
    try:
        # 실행 기본 정보
        exec_response = client.describe_execution(executionArn=execution_arn)
        
        # 실행 히스토리 (최근 10개 이벤트만)
        history_response = client.get_execution_history(
            executionArn=execution_arn,
            maxResults=10,
            reverseOrder=True
        )
        
        return {
            'execution_arn': execution_arn,
            'name': exec_response.get('name'),
            'status': exec_response.get('status'),
            'start_date': exec_response.get('startDate'),
            'stop_date': exec_response.get('stopDate'),
            'input': exec_response.get('input'),
            'output': exec_response.get('output'),
            'recent_events': history_response.get('events', [])
        }
        
    except Exception as e:
        print(f"Error getting execution details: {str(e)}")
        return {
            'execution_arn': execution_arn,
            'error': str(e)
        }

def process_activities_parallel(client, activities, max_workers=5):
    """Activity들을 병렬로 처리"""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_activity, client, activity) for activity in activities]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing activity: {str(e)}")
                continue
    
    return results

def analyze_single_activity(client, activity):
    """개별 Activity 상세 분석"""
    try:
        activity_arn = activity['activityArn']
        
        # Activity 상세 정보 조회
        activity_details = client.describe_activity(activityArn=activity_arn)
        
        # 태그 정보 조회
        tags = get_resource_tags(client, activity_arn)
        
        return {
            'name': activity.get('name'),
            'arn': activity_arn,
            'creation_date': activity_details.get('creationDate'),
            'tags': tags
        }
        
    except Exception as e:
        print(f"Error analyzing activity {activity.get('name', 'Unknown')}: {str(e)}")
        return {
            'name': activity.get('name', 'Unknown'),
            'arn': activity.get('activityArn', 'Unknown'),
            'error': str(e)
        }

def get_resource_tags(client, resource_arn):
    """리소스 태그 조회"""
    try:
        response = client.list_tags_for_resource(resourceArn=resource_arn)
        return response.get('tags', [])
    except Exception as e:
        print(f"Error getting tags for {resource_arn}: {str(e)}")
        return []

def assess_state_machine_security(sm_details, executions, tags):
    """State Machine 보안 평가"""
    assessment = {
        'security_score': 0,
        'findings': [],
        'recommendations': []
    }
    
    # 정의 검증 상태 확인
    if sm_details.get('definition'):
        assessment['security_score'] += 20
        assessment['findings'].append('State Machine definition exists')
    else:
        assessment['findings'].append('Missing State Machine definition')
        assessment['recommendations'].append('Ensure State Machine has proper definition')
    
    # IAM 역할 확인
    if sm_details.get('roleArn'):
        assessment['security_score'] += 20
        assessment['findings'].append('IAM role configured')
    else:
        assessment['findings'].append('No IAM role configured')
        assessment['recommendations'].append('Configure appropriate IAM role')
    
    # 실행 이력 확인
    if executions:
        successful_executions = [e for e in executions if e.get('status') == 'SUCCEEDED']
        success_rate = len(successful_executions) / len(executions) * 100
        
        if success_rate >= 80:
            assessment['security_score'] += 30
            assessment['findings'].append(f'High success rate: {success_rate:.1f}%')
        else:
            assessment['findings'].append(f'Low success rate: {success_rate:.1f}%')
            assessment['recommendations'].append('Investigate execution failures')
    
    # 태그 기반 분류
    security_tags = [tag for tag in tags if 'security' in tag.get('key', '').lower()]
    if security_tags:
        assessment['security_score'] += 15
        assessment['findings'].append('Security-related tags found')
    
    # 보안 관련 워크플로우 식별
    definition = sm_details.get('definition', '')
    if any(keyword in definition.lower() for keyword in ['security', 'incident', 'response', 'alert']):
        assessment['security_score'] += 15
        assessment['findings'].append('Security-related workflow detected')
    
    return assessment

def generate_security_summary(results):
    """보안 분석 요약 생성"""
    summary = {
        'total_state_machines': len(results.get('state_machines', [])),
        'total_activities': len(results.get('activities', [])),
        'security_workflows_identified': 0,
        'average_security_score': 0,
        'high_risk_findings': [],
        'recommendations': []
    }
    
    # State Machine 보안 점수 계산
    state_machines = results.get('state_machines', [])
    if state_machines:
        security_scores = []
        for sm in state_machines:
            security_assessment = sm.get('security_assessment', {})
            score = security_assessment.get('security_score', 0)
            security_scores.append(score)
            
            # 보안 워크플로우 식별
            if any(keyword in sm.get('name', '').lower() for keyword in ['security', 'incident', 'response']):
                summary['security_workflows_identified'] += 1
            
            # 고위험 발견사항
            if score < 50:
                summary['high_risk_findings'].append({
                    'state_machine': sm.get('name'),
                    'score': score,
                    'issues': security_assessment.get('findings', [])
                })
        
        summary['average_security_score'] = sum(security_scores) / len(security_scores)
    
    # 전체 권장사항
    if summary['average_security_score'] < 70:
        summary['recommendations'].append('Improve overall State Machine security configuration')
    
    if summary['security_workflows_identified'] == 0:
        summary['recommendations'].append('Consider implementing automated security response workflows')
    
    return summary

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
        'function': event.get('function', 'unknown'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'unknown'),
        'function': event.get('function', 'unknown'),
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
