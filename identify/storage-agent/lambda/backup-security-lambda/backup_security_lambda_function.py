import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    STORAGE-AGENT AWS Backup Security Analysis Lambda 함수
    22개 AWS Backup API를 통한 종합적인 백업 보안 상태 분석
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
        
        backup_client = session.client('backup', region_name=target_region)
        backup_search_client = session.client('backupsearch', region_name=target_region)
        
        # AWS Backup 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_backup_security_data_parallel(backup_client, backup_search_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeBackupSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"AWS Backup 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in AWS Backup security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_backup_security_data_parallel(backup_client, backup_search_client, target_region, current_time):
    """
    AWS Backup 보안 데이터를 병렬로 수집 - 22개 API 활용
    """
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('vault_security_management', lambda: analyze_vault_security_parallel(backup_client)),
        ('resource_protection_status', lambda: analyze_resource_protection_parallel(backup_client)),
        ('recovery_points_security', lambda: analyze_recovery_points_parallel(backup_client)),
        ('backup_jobs_audit', lambda: analyze_backup_jobs_parallel(backup_client)),
        ('backup_copy_management', lambda: analyze_backup_copy_parallel(backup_client)),
        ('restore_jobs_audit', lambda: analyze_restore_jobs_parallel(backup_client)),
        ('backup_plans_review', lambda: analyze_backup_plans_parallel(backup_client)),
        ('backup_search_features', lambda: analyze_backup_search_parallel(backup_search_client)),
    ]
    
    # 병렬 처리 실행
    results = process_backup_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': 22,
        'collection_method': 'parallel_processing',
        'backup_apis_used': 15,
        'backup_search_apis_used': 7
    }
    
    return {
        'function': 'analyzeBackupSecurity',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'vault_security': results.get('vault_security_management', {}),
        'resource_protection': results.get('resource_protection_status', {}),
        'recovery_points': results.get('recovery_points_security', {}),
        'backup_jobs': results.get('backup_jobs_audit', {}),
        'backup_copy': results.get('backup_copy_management', {}),
        'restore_jobs': results.get('restore_jobs_audit', {}),
        'backup_plans': results.get('backup_plans_review', {}),
        'backup_search': results.get('backup_search_features', {}),
        'collection_summary': collection_summary
    }

def process_backup_parallel(tasks, max_workers=8):
    """AWS Backup 데이터 수집 작업을 병렬로 처리"""
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

# 볼트 보안 관리 (3개 API)
def analyze_vault_security_parallel(client):
    """백업 볼트 보안 관리 분석"""
    vault_tasks = [
        ('backup_vaults', lambda: describe_backup_vaults_safe(client)),
        ('vault_access_policies', lambda: get_vault_access_policies_safe(client)),
        ('vault_notifications', lambda: get_vault_notifications_safe(client))
    ]
    
    return execute_parallel_tasks(vault_tasks, max_workers=3)

# 리소스 보호 현황 (2개 API)
def analyze_resource_protection_parallel(client):
    """리소스 보호 현황 분석"""
    protection_tasks = [
        ('protected_resources', lambda: list_protected_resources_safe(client)),
        ('protected_resource_details', lambda: describe_protected_resources_safe(client))
    ]
    
    return execute_parallel_tasks(protection_tasks, max_workers=2)

# 복구 지점 보안 (2개 API)
def analyze_recovery_points_parallel(client):
    """복구 지점 보안 분석"""
    recovery_tasks = [
        ('recovery_points_by_resource', lambda: list_recovery_points_by_resource_safe(client)),
        ('recovery_point_details', lambda: describe_recovery_points_safe(client))
    ]
    
    return execute_parallel_tasks(recovery_tasks, max_workers=2)

# 백업 작업 감사 (2개 API)
def analyze_backup_jobs_parallel(client):
    """백업 작업 감사 분석"""
    backup_job_tasks = [
        ('backup_jobs', lambda: list_backup_jobs_safe(client)),
        ('backup_job_details', lambda: describe_backup_jobs_safe(client))
    ]
    
    return execute_parallel_tasks(backup_job_tasks, max_workers=2)

# 백업 복사 관리 (2개 API)
def analyze_backup_copy_parallel(client):
    """백업 복사 관리 분석"""
    copy_tasks = [
        ('copy_jobs', lambda: list_copy_jobs_safe(client)),
        ('copy_job_details', lambda: describe_copy_jobs_safe(client))
    ]
    
    return execute_parallel_tasks(copy_tasks, max_workers=2)

# 복원 작업 감사 (2개 API)
def analyze_restore_jobs_parallel(client):
    """복원 작업 감사 분석"""
    restore_tasks = [
        ('restore_jobs', lambda: list_restore_jobs_safe(client)),
        ('restore_job_details', lambda: describe_restore_jobs_safe(client))
    ]
    
    return execute_parallel_tasks(restore_tasks, max_workers=2)

# 백업 계획 검토 (2개 API)
def analyze_backup_plans_parallel(client):
    """백업 계획 검토 분석"""
    plan_tasks = [
        ('backup_plans', lambda: list_backup_plans_safe(client)),
        ('backup_plan_details', lambda: get_backup_plans_safe(client))
    ]
    
    return execute_parallel_tasks(plan_tasks, max_workers=2)

# 백업 검색 기능 (7개 API)
def analyze_backup_search_parallel(client):
    """백업 검색 및 내보내기 기능 분석"""
    search_tasks = [
        ('search_jobs', lambda: list_search_jobs_safe(client)),
        ('search_job_details', lambda: get_search_jobs_safe(client)),
        ('search_results', lambda: list_search_job_results_safe(client)),
        ('search_backups', lambda: list_search_job_backups_safe(client)),
        ('export_jobs', lambda: list_search_result_export_jobs_safe(client)),
        ('export_job_details', lambda: get_search_result_export_jobs_safe(client)),
        ('resource_tags', lambda: list_tags_for_resource_safe(client))
    ]
    
    return execute_parallel_tasks(search_tasks, max_workers=7)

# 개별 API 안전 호출 함수들
def describe_backup_vaults_safe(client):
    """DescribeBackupVault 안전 호출"""
    try:
        response = client.list_backup_vaults()
        vaults = response.get('BackupVaultList', [])
        
        vault_details = []
        for vault in vaults:
            try:
                vault_detail = client.describe_backup_vault(BackupVaultName=vault['BackupVaultName'])
                vault_details.append(vault_detail)
            except Exception as e:
                print(f"Error describing vault {vault['BackupVaultName']}: {str(e)}")
                continue
        
        return {
            'total_vaults': len(vaults),
            'vault_list': vaults,
            'vault_details': vault_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_vault_access_policies_safe(client):
    """GetBackupVaultAccessPolicy 안전 호출"""
    try:
        vaults_response = client.list_backup_vaults()
        vaults = vaults_response.get('BackupVaultList', [])
        
        vault_policies = []
        for vault in vaults:
            try:
                policy_response = client.get_backup_vault_access_policy(
                    BackupVaultName=vault['BackupVaultName']
                )
                vault_policies.append({
                    'vault_name': vault['BackupVaultName'],
                    'policy': policy_response.get('Policy'),
                    'backup_vault_arn': policy_response.get('BackupVaultArn')
                })
            except client.exceptions.ResourceNotFoundException:
                vault_policies.append({
                    'vault_name': vault['BackupVaultName'],
                    'policy': None,
                    'note': 'No access policy set'
                })
            except Exception as e:
                print(f"Error getting policy for vault {vault['BackupVaultName']}: {str(e)}")
                continue
        
        return {
            'vault_policies': vault_policies,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_vault_notifications_safe(client):
    """GetBackupVaultNotifications 안전 호출"""
    try:
        vaults_response = client.list_backup_vaults()
        vaults = vaults_response.get('BackupVaultList', [])
        
        vault_notifications = []
        for vault in vaults:
            try:
                notification_response = client.get_backup_vault_notifications(
                    BackupVaultName=vault['BackupVaultName']
                )
                vault_notifications.append({
                    'vault_name': vault['BackupVaultName'],
                    'sns_topic_arn': notification_response.get('SNSTopicArn'),
                    'backup_vault_events': notification_response.get('BackupVaultEvents', [])
                })
            except client.exceptions.ResourceNotFoundException:
                vault_notifications.append({
                    'vault_name': vault['BackupVaultName'],
                    'sns_topic_arn': None,
                    'note': 'No notifications configured'
                })
            except Exception as e:
                print(f"Error getting notifications for vault {vault['BackupVaultName']}: {str(e)}")
                continue
        
        return {
            'vault_notifications': vault_notifications,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_protected_resources_safe(client):
    """ListProtectedResources 안전 호출"""
    try:
        response = client.list_protected_resources()
        protected_resources = response.get('Results', [])
        
        return {
            'total_protected_resources': len(protected_resources),
            'protected_resources': protected_resources,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_protected_resources_safe(client):
    """DescribeProtectedResource 안전 호출"""
    try:
        protected_response = client.list_protected_resources()
        protected_resources = protected_response.get('Results', [])
        
        if not protected_resources:
            return {'status': 'no_protected_resources', 'message': '보호된 리소스가 없습니다.'}
        
        resource_details = []
        for resource in protected_resources[:10]:  # 최대 10개만 상세 조회
            try:
                detail_response = client.describe_protected_resource(
                    ResourceArn=resource['ResourceArn']
                )
                resource_details.append(detail_response)
            except Exception as e:
                print(f"Error describing protected resource {resource['ResourceArn']}: {str(e)}")
                continue
        
        return {
            'protected_resource_details': resource_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_recovery_points_by_resource_safe(client):
    """ListRecoveryPointsByResource 안전 호출"""
    try:
        protected_response = client.list_protected_resources()
        protected_resources = protected_response.get('Results', [])
        
        if not protected_resources:
            return {'status': 'no_protected_resources', 'message': '보호된 리소스가 없습니다.'}
        
        recovery_points_by_resource = []
        for resource in protected_resources[:5]:  # 최대 5개 리소스만
            try:
                rp_response = client.list_recovery_points_by_resource(
                    ResourceArn=resource['ResourceArn']
                )
                recovery_points_by_resource.append({
                    'resource_arn': resource['ResourceArn'],
                    'recovery_points': rp_response.get('RecoveryPoints', [])
                })
            except Exception as e:
                print(f"Error listing recovery points for {resource['ResourceArn']}: {str(e)}")
                continue
        
        return {
            'recovery_points_by_resource': recovery_points_by_resource,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_recovery_points_safe(client):
    """DescribeRecoveryPoint 안전 호출"""
    try:
        # 백업 볼트 목록 조회
        vaults_response = client.list_backup_vaults()
        vaults = vaults_response.get('BackupVaultList', [])
        
        if not vaults:
            return {'status': 'no_vaults', 'message': '백업 볼트가 없습니다.'}
        
        recovery_point_details = []
        for vault in vaults[:3]:  # 최대 3개 볼트만
            try:
                # 각 볼트의 복구 지점 목록 조회
                rp_list_response = client.list_recovery_points_by_backup_vault(
                    BackupVaultName=vault['BackupVaultName']
                )
                recovery_points = rp_list_response.get('RecoveryPoints', [])
                
                # 각 복구 지점의 상세 정보 조회 (최대 3개)
                for rp in recovery_points[:3]:
                    try:
                        rp_detail = client.describe_recovery_point(
                            BackupVaultName=vault['BackupVaultName'],
                            RecoveryPointArn=rp['RecoveryPointArn']
                        )
                        recovery_point_details.append(rp_detail)
                    except Exception as e:
                        print(f"Error describing recovery point {rp['RecoveryPointArn']}: {str(e)}")
                        continue
            except Exception as e:
                print(f"Error listing recovery points for vault {vault['BackupVaultName']}: {str(e)}")
                continue
        
        return {
            'recovery_point_details': recovery_point_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_backup_jobs_safe(client):
    """ListBackupJobs 안전 호출"""
    try:
        response = client.list_backup_jobs()
        backup_jobs = response.get('BackupJobs', [])
        
        return {
            'total_backup_jobs': len(backup_jobs),
            'backup_jobs': backup_jobs,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_backup_jobs_safe(client):
    """DescribeBackupJob 안전 호출"""
    try:
        jobs_response = client.list_backup_jobs()
        backup_jobs = jobs_response.get('BackupJobs', [])
        
        if not backup_jobs:
            return {'status': 'no_backup_jobs', 'message': '백업 작업이 없습니다.'}
        
        job_details = []
        for job in backup_jobs[:5]:  # 최대 5개만 상세 조회
            try:
                job_detail = client.describe_backup_job(BackupJobId=job['BackupJobId'])
                job_details.append(job_detail)
            except Exception as e:
                print(f"Error describing backup job {job['BackupJobId']}: {str(e)}")
                continue
        
        return {
            'backup_job_details': job_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_copy_jobs_safe(client):
    """ListCopyJobs 안전 호출"""
    try:
        response = client.list_copy_jobs()
        copy_jobs = response.get('CopyJobs', [])
        
        return {
            'total_copy_jobs': len(copy_jobs),
            'copy_jobs': copy_jobs,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_copy_jobs_safe(client):
    """DescribeCopyJob 안전 호출"""
    try:
        jobs_response = client.list_copy_jobs()
        copy_jobs = jobs_response.get('CopyJobs', [])
        
        if not copy_jobs:
            return {'status': 'no_copy_jobs', 'message': '복사 작업이 없습니다.'}
        
        job_details = []
        for job in copy_jobs[:5]:  # 최대 5개만 상세 조회
            try:
                job_detail = client.describe_copy_job(CopyJobId=job['CopyJobId'])
                job_details.append(job_detail)
            except Exception as e:
                print(f"Error describing copy job {job['CopyJobId']}: {str(e)}")
                continue
        
        return {
            'copy_job_details': job_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_restore_jobs_safe(client):
    """ListRestoreJobs 안전 호출"""
    try:
        response = client.list_restore_jobs()
        restore_jobs = response.get('RestoreJobs', [])
        
        return {
            'total_restore_jobs': len(restore_jobs),
            'restore_jobs': restore_jobs,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def describe_restore_jobs_safe(client):
    """DescribeRestoreJob 안전 호출"""
    try:
        jobs_response = client.list_restore_jobs()
        restore_jobs = jobs_response.get('RestoreJobs', [])
        
        if not restore_jobs:
            return {'status': 'no_restore_jobs', 'message': '복원 작업이 없습니다.'}
        
        job_details = []
        for job in restore_jobs[:5]:  # 최대 5개만 상세 조회
            try:
                job_detail = client.describe_restore_job(RestoreJobId=job['RestoreJobId'])
                job_details.append(job_detail)
            except Exception as e:
                print(f"Error describing restore job {job['RestoreJobId']}: {str(e)}")
                continue
        
        return {
            'restore_job_details': job_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_backup_plans_safe(client):
    """ListBackupPlans 안전 호출"""
    try:
        response = client.list_backup_plans()
        backup_plans = response.get('BackupPlansList', [])
        
        return {
            'total_backup_plans': len(backup_plans),
            'backup_plans': backup_plans,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_backup_plans_safe(client):
    """GetBackupPlan 안전 호출"""
    try:
        plans_response = client.list_backup_plans()
        backup_plans = plans_response.get('BackupPlansList', [])
        
        if not backup_plans:
            return {'status': 'no_backup_plans', 'message': '백업 계획이 없습니다.'}
        
        plan_details = []
        for plan in backup_plans[:5]:  # 최대 5개만 상세 조회
            try:
                plan_detail = client.get_backup_plan(BackupPlanId=plan['BackupPlanId'])
                plan_details.append(plan_detail)
            except Exception as e:
                print(f"Error getting backup plan {plan['BackupPlanId']}: {str(e)}")
                continue
        
        return {
            'backup_plan_details': plan_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# Backup Search API 함수들
def list_search_jobs_safe(client):
    """ListSearchJobs 안전 호출"""
    try:
        response = client.list_search_jobs()
        search_jobs = response.get('SearchJobs', [])
        
        return {
            'total_search_jobs': len(search_jobs),
            'search_jobs': search_jobs,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_search_jobs_safe(client):
    """GetSearchJob 안전 호출"""
    try:
        jobs_response = client.list_search_jobs()
        search_jobs = jobs_response.get('SearchJobs', [])
        
        if not search_jobs:
            return {'status': 'no_search_jobs', 'message': '검색 작업이 없습니다.'}
        
        job_details = []
        for job in search_jobs[:3]:  # 최대 3개만 상세 조회
            try:
                job_detail = client.get_search_job(SearchJobIdentifier=job['SearchJobIdentifier'])
                job_details.append(job_detail)
            except Exception as e:
                print(f"Error getting search job {job['SearchJobIdentifier']}: {str(e)}")
                continue
        
        return {
            'search_job_details': job_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_search_job_results_safe(client):
    """ListSearchJobResults 안전 호출"""
    try:
        jobs_response = client.list_search_jobs()
        search_jobs = jobs_response.get('SearchJobs', [])
        
        if not search_jobs:
            return {'status': 'no_search_jobs', 'message': '검색 작업이 없습니다.'}
        
        job_results = []
        for job in search_jobs[:3]:  # 최대 3개만
            try:
                results_response = client.list_search_job_results(
                    SearchJobIdentifier=job['SearchJobIdentifier']
                )
                job_results.append({
                    'search_job_id': job['SearchJobIdentifier'],
                    'results': results_response.get('Results', [])
                })
            except Exception as e:
                print(f"Error listing results for search job {job['SearchJobIdentifier']}: {str(e)}")
                continue
        
        return {
            'search_job_results': job_results,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_search_job_backups_safe(client):
    """ListSearchJobBackups 안전 호출"""
    try:
        jobs_response = client.list_search_jobs()
        search_jobs = jobs_response.get('SearchJobs', [])
        
        if not search_jobs:
            return {'status': 'no_search_jobs', 'message': '검색 작업이 없습니다.'}
        
        job_backups = []
        for job in search_jobs[:3]:  # 최대 3개만
            try:
                backups_response = client.list_search_job_backups(
                    SearchJobIdentifier=job['SearchJobIdentifier']
                )
                job_backups.append({
                    'search_job_id': job['SearchJobIdentifier'],
                    'backups': backups_response.get('Backups', [])
                })
            except Exception as e:
                print(f"Error listing backups for search job {job['SearchJobIdentifier']}: {str(e)}")
                continue
        
        return {
            'search_job_backups': job_backups,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_search_result_export_jobs_safe(client):
    """ListSearchResultExportJobs 안전 호출"""
    try:
        response = client.list_search_result_export_jobs()
        export_jobs = response.get('ExportJobs', [])
        
        return {
            'total_export_jobs': len(export_jobs),
            'export_jobs': export_jobs,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_search_result_export_jobs_safe(client):
    """GetSearchResultExportJob 안전 호출"""
    try:
        jobs_response = client.list_search_result_export_jobs()
        export_jobs = jobs_response.get('ExportJobs', [])
        
        if not export_jobs:
            return {'status': 'no_export_jobs', 'message': '내보내기 작업이 없습니다.'}
        
        job_details = []
        for job in export_jobs[:3]:  # 최대 3개만 상세 조회
            try:
                job_detail = client.get_search_result_export_job(
                    ExportJobIdentifier=job['ExportJobIdentifier']
                )
                job_details.append(job_detail)
            except Exception as e:
                print(f"Error getting export job {job['ExportJobIdentifier']}: {str(e)}")
                continue
        
        return {
            'export_job_details': job_details,
            'status': 'success'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def list_tags_for_resource_safe(client):
    """ListTagsForResource 안전 호출"""
    try:
        # 검색 작업이나 내보내기 작업의 태그 조회 시도
        jobs_response = client.list_search_jobs()
        search_jobs = jobs_response.get('SearchJobs', [])
        
        if not search_jobs:
            return {'status': 'no_resources', 'message': '태그를 조회할 리소스가 없습니다.'}
        
        resource_tags = []
        for job in search_jobs[:3]:  # 최대 3개만
            try:
                # 검색 작업 ARN 구성 (예시)
                resource_arn = f"arn:aws:backup-search:*:*:search-job/{job['SearchJobIdentifier']}"
                tags_response = client.list_tags_for_resource(ResourceArn=resource_arn)
                resource_tags.append({
                    'resource_arn': resource_arn,
                    'tags': tags_response.get('Tags', {})
                })
            except Exception as e:
                print(f"Error listing tags for resource: {str(e)}")
                continue
        
        return {
            'resource_tags': resource_tags,
            'status': 'success'
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
        'function': event.get('function', 'analyzeBackupSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'backup-security-analysis'),
        'function': event.get('function', 'analyzeBackupSecurity'),
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
