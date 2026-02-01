import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
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
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다.")
        
        # 고객 자격증명으로 AWS 세션 생성 (IAM은 글로벌 서비스)
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        
        iam_client = session.client('iam')
        
        # IAM 보안 데이터 병렬 수집
        raw_data = collect_iam_raw_data_parallel(iam_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeIAMSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"IAM 보안 분석 함수 실행 중 오류 발생: {str(e)}"
        print(error_message)
        return create_bedrock_error_response(event, error_message)

def collect_iam_raw_data_parallel(iam_client, target_region):
    """IAM 보안 관련 원시 데이터를 병렬로 수집"""
    
    # 1단계: 기본 엔티티 목록 수집
    users = get_all_users(iam_client)
    roles = get_all_roles(iam_client)
    groups = get_all_groups(iam_client)
    policies = get_all_policies(iam_client)
    
    # 2단계: 각 엔티티별 상세 정보 병렬 수집
    users_details = process_users_parallel(iam_client, users)
    roles_details = process_roles_parallel(iam_client, roles)
    groups_details = process_groups_parallel(iam_client, groups)
    policies_details = process_policies_parallel(iam_client, policies)
    
    # 3단계: 계정 레벨 보안 정보 수집
    account_security = get_account_security_info(iam_client)
    
    # 수집 요약 정보
    collection_summary = {
        'total_users': len(users),
        'total_roles': len(roles),
        'total_groups': len(groups),
        'total_policies': len(policies),
        'target_region': target_region,
        'collection_timestamp': 'now',
        'apis_used': 41
    }
    
    return {
        'users_analysis': users_details,
        'roles_analysis': roles_details,
        'groups_analysis': groups_details,
        'policies_analysis': policies_details,
        'account_security': account_security,
        'collection_summary': collection_summary
    }

def get_all_users(iam_client):
    """모든 IAM 사용자 목록 조회"""
    try:
        paginator = iam_client.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page.get('Users', []))
        return users
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return []

def get_all_roles(iam_client):
    """모든 IAM 역할 목록 조회"""
    try:
        paginator = iam_client.get_paginator('list_roles')
        roles = []
        for page in paginator.paginate():
            roles.extend(page.get('Roles', []))
        return roles
    except Exception as e:
        print(f"Error getting roles: {str(e)}")
        return []

def get_all_groups(iam_client):
    """모든 IAM 그룹 목록 조회"""
    try:
        paginator = iam_client.get_paginator('list_groups')
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get('Groups', []))
        return groups
    except Exception as e:
        print(f"Error getting groups: {str(e)}")
        return []

def get_all_policies(iam_client):
    """모든 고객 관리형 정책 목록 조회"""
    try:
        paginator = iam_client.get_paginator('list_policies')
        policies = []
        for page in paginator.paginate(Scope='Local'):
            policies.extend(page.get('Policies', []))
        return policies
    except Exception as e:
        print(f"Error getting policies: {str(e)}")
        return []

def process_users_parallel(iam_client, users):
    """사용자별 상세 보안 정보를 병렬로 수집"""
    if not users:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_user_security_details, iam_client, user) for user in users]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing user: {str(e)}")
                continue
    
    return results

def get_user_security_details(iam_client, user):
    """개별 사용자의 보안 상세 정보 수집"""
    try:
        username = user['UserName']
        user_details = {
            'user_info': user,
            'access_keys': [],
            'mfa_devices': [],
            'attached_policies': [],
            'inline_policies': [],
            'groups': [],
            'login_profile': None,
            'ssh_keys': [],
            'signing_certificates': [],
            'service_credentials': []
        }
        
        # 1. 액세스 키 정보 (API 1-2)
        try:
            access_keys_response = iam_client.list_access_keys(UserName=username)
            for key in access_keys_response.get('AccessKeyMetadata', []):
                try:
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    key['LastUsed'] = last_used.get('AccessKeyLastUsed', {})
                except Exception as e:
                    key['LastUsed'] = {'Error': str(e)}
                user_details['access_keys'].append(key)
        except Exception as e:
            user_details['access_keys'] = {'Error': str(e)}
        
        # 2. MFA 디바이스 정보 (API 3-5)
        try:
            mfa_devices = iam_client.list_mfa_devices(UserName=username)
            user_details['mfa_devices'] = mfa_devices.get('MFADevices', [])
        except Exception as e:
            user_details['mfa_devices'] = {'Error': str(e)}
        
        # 3. 연결된 정책 (API 10)
        try:
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            user_details['attached_policies'] = attached_policies.get('AttachedPolicies', [])
        except Exception as e:
            user_details['attached_policies'] = {'Error': str(e)}
        
        # 4. 인라인 정책 (API 15, 18)
        try:
            inline_policies = iam_client.list_user_policies(UserName=username)
            policy_names = inline_policies.get('PolicyNames', [])
            user_details['inline_policies'] = []
            
            for policy_name in policy_names:
                try:
                    policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                    user_details['inline_policies'].append(policy_doc)
                except Exception as e:
                    user_details['inline_policies'].append({'PolicyName': policy_name, 'Error': str(e)})
        except Exception as e:
            user_details['inline_policies'] = {'Error': str(e)}
        
        # 5. 그룹 멤버십 (API 41)
        try:
            groups = iam_client.list_groups_for_user(UserName=username)
            user_details['groups'] = groups.get('Groups', [])
        except Exception as e:
            user_details['groups'] = {'Error': str(e)}
        
        # 6. 로그인 프로필 (API 39)
        try:
            login_profile = iam_client.get_login_profile(UserName=username)
            user_details['login_profile'] = login_profile.get('LoginProfile', {})
        except iam_client.exceptions.NoSuchEntityException:
            user_details['login_profile'] = None
        except Exception as e:
            user_details['login_profile'] = {'Error': str(e)}
        
        # 7. SSH 공개 키 (API 21-22)
        try:
            ssh_keys = iam_client.list_ssh_public_keys(UserName=username)
            user_details['ssh_keys'] = ssh_keys.get('SSHPublicKeys', [])
        except Exception as e:
            user_details['ssh_keys'] = {'Error': str(e)}
        
        # 8. 서명 인증서 (API 23)
        try:
            signing_certs = iam_client.list_signing_certificates(UserName=username)
            user_details['signing_certificates'] = signing_certs.get('Certificates', [])
        except Exception as e:
            user_details['signing_certificates'] = {'Error': str(e)}
        
        # 9. 서비스별 자격증명 (API 38)
        try:
            service_creds = iam_client.list_service_specific_credentials(UserName=username)
            user_details['service_credentials'] = service_creds.get('ServiceSpecificCredentials', [])
        except Exception as e:
            user_details['service_credentials'] = {'Error': str(e)}
        
        return user_details
        
    except Exception as e:
        print(f"Error getting user details for {user.get('UserName', 'unknown')}: {str(e)}")
        return None

def process_roles_parallel(iam_client, roles):
    """역할별 상세 보안 정보를 병렬로 수집"""
    if not roles:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_role_security_details, iam_client, role) for role in roles]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing role: {str(e)}")
                continue
    
    return results

def get_role_security_details(iam_client, role):
    """개별 역할의 보안 상세 정보 수집"""
    try:
        role_name = role['RoleName']
        role_details = {
            'role_info': role,
            'attached_policies': [],
            'inline_policies': []
        }
        
        # 1. 연결된 정책 (API 9)
        try:
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            role_details['attached_policies'] = attached_policies.get('AttachedPolicies', [])
        except Exception as e:
            role_details['attached_policies'] = {'Error': str(e)}
        
        # 2. 인라인 정책 (API 14, 17)
        try:
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            policy_names = inline_policies.get('PolicyNames', [])
            role_details['inline_policies'] = []
            
            for policy_name in policy_names:
                try:
                    policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    role_details['inline_policies'].append(policy_doc)
                except Exception as e:
                    role_details['inline_policies'].append({'PolicyName': policy_name, 'Error': str(e)})
        except Exception as e:
            role_details['inline_policies'] = {'Error': str(e)}
        
        # 3. 역할 상세 정보 (신뢰 정책 포함) (API 33)
        try:
            role_detail = iam_client.get_role(RoleName=role_name)
            role_details['role_detail'] = role_detail.get('Role', {})
        except Exception as e:
            role_details['role_detail'] = {'Error': str(e)}
        
        return role_details
        
    except Exception as e:
        print(f"Error getting role details for {role.get('RoleName', 'unknown')}: {str(e)}")
        return None

def process_groups_parallel(iam_client, groups):
    """그룹별 상세 보안 정보를 병렬로 수집"""
    if not groups:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_group_security_details, iam_client, group) for group in groups]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing group: {str(e)}")
                continue
    
    return results

def get_group_security_details(iam_client, group):
    """개별 그룹의 보안 상세 정보 수집"""
    try:
        group_name = group['GroupName']
        group_details = {
            'group_info': group,
            'attached_policies': [],
            'inline_policies': []
        }
        
        # 1. 연결된 정책 (API 8)
        try:
            attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            group_details['attached_policies'] = attached_policies.get('AttachedPolicies', [])
        except Exception as e:
            group_details['attached_policies'] = {'Error': str(e)}
        
        # 2. 인라인 정책 (API 13, 16)
        try:
            inline_policies = iam_client.list_group_policies(GroupName=group_name)
            policy_names = inline_policies.get('PolicyNames', [])
            group_details['inline_policies'] = []
            
            for policy_name in policy_names:
                try:
                    policy_doc = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                    group_details['inline_policies'].append(policy_doc)
                except Exception as e:
                    group_details['inline_policies'].append({'PolicyName': policy_name, 'Error': str(e)})
        except Exception as e:
            group_details['inline_policies'] = {'Error': str(e)}
        
        return group_details
        
    except Exception as e:
        print(f"Error getting group details for {group.get('GroupName', 'unknown')}: {str(e)}")
        return None

def process_policies_parallel(iam_client, policies):
    """정책별 상세 보안 정보를 병렬로 수집"""
    if not policies:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_policy_security_details, iam_client, policy) for policy in policies]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing policy: {str(e)}")
                continue
    
    return results

def get_policy_security_details(iam_client, policy):
    """개별 정책의 보안 상세 정보 수집"""
    try:
        policy_arn = policy['Arn']
        policy_details = {
            'policy_info': policy,
            'policy_version': None,
            'entities_for_policy': []
        }
        
        # 1. 정책 내용 (API 6-7)
        try:
            policy_detail = iam_client.get_policy(PolicyArn=policy_arn)
            default_version = policy_detail['Policy']['DefaultVersionId']
            
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version
            )
            policy_details['policy_version'] = policy_version.get('PolicyVersion', {})
        except Exception as e:
            policy_details['policy_version'] = {'Error': str(e)}
        
        # 2. 정책이 연결된 엔티티 (API 11)
        try:
            entities = iam_client.list_entities_for_policy(PolicyArn=policy_arn)
            policy_details['entities_for_policy'] = entities
        except Exception as e:
            policy_details['entities_for_policy'] = {'Error': str(e)}
        
        return policy_details
        
    except Exception as e:
        print(f"Error getting policy details for {policy.get('PolicyName', 'unknown')}: {str(e)}")
        return None

def get_account_security_info(iam_client):
    """계정 레벨 보안 정보 수집"""
    account_info = {}
    
    # 1. 계정 패스워드 정책 (API 24)
    try:
        password_policy = iam_client.get_account_password_policy()
        account_info['password_policy'] = password_policy.get('PasswordPolicy', {})
    except iam_client.exceptions.NoSuchEntityException:
        account_info['password_policy'] = None
    except Exception as e:
        account_info['password_policy'] = {'Error': str(e)}
    
    # 2. 계정 권한 세부사항 (API 25)
    try:
        auth_details = iam_client.get_account_authorization_details()
        account_info['authorization_details'] = auth_details
    except Exception as e:
        account_info['authorization_details'] = {'Error': str(e)}
    
    # 3. 자격증명 보고서 (API 26)
    try:
        # 보고서 생성 요청
        iam_client.generate_credential_report()
        # 보고서 조회 (생성에 시간이 걸릴 수 있음)
        credential_report = iam_client.get_credential_report()
        account_info['credential_report'] = credential_report
    except Exception as e:
        account_info['credential_report'] = {'Error': str(e)}
    
    # 4. 가상 MFA 디바이스 목록 (API 5)
    try:
        virtual_mfa = iam_client.list_virtual_mfa_devices()
        account_info['virtual_mfa_devices'] = virtual_mfa.get('VirtualMFADevices', [])
    except Exception as e:
        account_info['virtual_mfa_devices'] = {'Error': str(e)}
    
    # 5. 서버 인증서 목록 (API 19-20)
    try:
        server_certs = iam_client.list_server_certificates()
        account_info['server_certificates'] = server_certs.get('ServerCertificateMetadataList', [])
    except Exception as e:
        account_info['server_certificates'] = {'Error': str(e)}
    
    # 6. OIDC 공급자 (API 34, 36)
    try:
        oidc_providers = iam_client.list_open_id_connect_providers()
        account_info['oidc_providers'] = oidc_providers.get('OpenIDConnectProviderList', [])
    except Exception as e:
        account_info['oidc_providers'] = {'Error': str(e)}
    
    # 7. SAML 공급자 (API 35, 37)
    try:
        saml_providers = iam_client.list_saml_providers()
        account_info['saml_providers'] = saml_providers.get('SAMLProviderList', [])
    except Exception as e:
        account_info['saml_providers'] = {'Error': str(e)}
    
    return account_info

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
