from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from .models import Organization, Project, Department, Role, UserProfile, Client, SLA, UserProfile, Ticket
from datetime import datetime
from .forms import TicketForm, UpdateTicketForm, CommentForm
from django.http import JsonResponse
import json
import os
from openai import OpenAI
import re
import requests
import pymongo

def base(request):
    return render(request, 'main.html')

def alert(request):
    return render(request, 'description.html')


# ------------------ Organization CRUD ------------------

def create_organization(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if not name or not description:
            return HttpResponse("Error: All fields are required", status=400)

        organization = Organization.objects.create(name=name, description=description)
        return redirect('organization_list')

    return render(request, 'create_organization.html')


def organization_list(request):
    organizations = Organization.objects.all()
    return render(request, 'organization_list.html', {'organizations': organizations})


def edit_organization(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)

    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')

        if not name or not description:
            return HttpResponse("Error: All fields are required", status=400)

        organization.name = name
        organization.description = description
        organization.save()
        return redirect('organization_list')

    return render(request, 'edit_organization.html', {'organization': organization})


def delete_organization(request, org_id):
    organization = get_object_or_404(Organization, id=org_id)
    organization.delete()
    return redirect('organization_list')


# ------------------ Project CRUD ------------------

def create_project(request):
    if request.method == 'POST':
        organization_id = request.POST.get('organization_id')
        name = request.POST.get('name')
        project_key = request.POST.get('project_key')

        if not name or not project_key or not organization_id:
            return HttpResponse("Error: All fields are required", status=400)

        organization = get_object_or_404(Organization, id=organization_id)

        project = Project.objects.create(organization=organization, name=name, project_key=project_key)
        return redirect('project_list')

    organizations = Organization.objects.all()
    return render(request, 'create_project.html', {'organizations': organizations})


def project_list(request):
    projects = Project.objects.all()
    return render(request, 'project_list.html', {'projects': projects})


def edit_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)

    if request.method == 'POST':
        project.name = request.POST.get('name')
        project.project_key = request.POST.get('project_key')
        project.save()
        return redirect('project_list')

    organizations = Organization.objects.all()
    return render(request, 'edit_project.html', {'project': project, 'organizations': organizations})


def delete_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    project.delete()
    return redirect('project_list')


# ------------------ Department CRUD ------------------

def create_department(request):
    if request.method == 'POST':
        name = request.POST.get('name')

        if not name:
            return HttpResponse("Error: Department name is required", status=400)

        department = Department.objects.create(name=name)
        return redirect('department_list')

    return render(request, 'create_department.html')


def department_list(request):
    departments = Department.objects.all()
    return render(request, 'department_list.html', {'departments': departments})


def edit_department(request, department_id):
    department = get_object_or_404(Department, id=department_id)

    if request.method == 'POST':
        department.name = request.POST.get('name')
        department.save()
        return redirect('department_list')

    return render(request, 'edit_department.html', {'department': department})


def delete_department(request, department_id):
    department = get_object_or_404(Department, id=department_id)
    department.delete()
    return redirect('department_list')


# ------------------ Role CRUD ------------------

def create_role(request):
    if request.method == 'POST':
        department_id = request.POST.get('department_id')
        role_name = request.POST.get('role_name')

        if not department_id or not role_name:
            return HttpResponse("Error: All fields are required", status=400)

        department = get_object_or_404(Department, id=department_id)

        role = Role.objects.create(department=department, name=role_name)
        return redirect('role_list')

    departments = Department.objects.all()
    return render(request, 'create_role.html', {'departments': departments})


def role_list(request):
    roles = Role.objects.all()
    return render(request, 'role_list.html', {'roles': roles})


def edit_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)

    if request.method == 'POST':
        role.name = request.POST.get('role_name')
        role.save()
        return redirect('role_list')

    departments = Department.objects.all()
    return render(request, 'edit_role.html', {'role': role, 'departments': departments})


def delete_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    role.delete()
    return redirect('role_list')


# ------------------ User CRUD ------------------

def create_user(request):
    if request.method == 'POST':
        organization_id = request.POST.get('organization_id')
        department_id = request.POST.get('department_id')
        role_id = request.POST.get('role_id')
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        date_of_birth = request.POST.get('date_of_birth')
        date_of_joining = request.POST.get('date_of_joining')
        status = request.POST.get('status')

        if not (organization_id and department_id and role_id and username and email and phone_number and date_of_birth and date_of_joining):
            return HttpResponse("Error: All fields are required", status=400)

        organization = get_object_or_404(Organization, id=organization_id)
        department = get_object_or_404(Department, id=department_id)
        role = get_object_or_404(Role, id=role_id)

        user = User.objects.create_user(username=username, email=email)
        user_profile = UserProfile.objects.create(
            organization=organization,
            department=department,
            role=role,
            user=user,
            phone_number=phone_number,
            date_of_birth=datetime.strptime(date_of_birth, '%Y-%m-%d'),
            date_of_joining=datetime.strptime(date_of_joining, '%Y-%m-%d'),
            status=status
        )
        return redirect('user_list')

    organizations = Organization.objects.all()
    departments = Department.objects.all()
    roles = Role.objects.all()
    return render(request, 'create_user.html', {'organizations': organizations, 'departments': departments, 'roles': roles})


def user_list(request):
    users = UserProfile.objects.all()
    return render(request, 'user_list.html', {'users': users})


def edit_user(request, user_id):
    user_profile = get_object_or_404(UserProfile, id=user_id)

    if request.method == 'POST':
        user_profile.user.username = request.POST.get('username')
        user_profile.user.email = request.POST.get('email')
        user_profile.phone_number = request.POST.get('phone_number')
        user_profile.date_of_birth = datetime.strptime(request.POST.get('date_of_birth'), '%Y-%m-%d')
        user_profile.date_of_joining = datetime.strptime(request.POST.get('date_of_joining'), '%Y-%m-%d')
        user_profile.status = request.POST.get('status')
        user_profile.save()

        return redirect('user_list')

    organizations = Organization.objects.all()
    departments = Department.objects.all()
    roles = Role.objects.all()
    return render(request, 'edit_user.html', {'user_profile': user_profile, 'organizations': organizations, 'departments': departments, 'roles': roles})


def delete_user(request, user_id):
    user_profile = get_object_or_404(UserProfile, id=user_id)
    user_profile.delete()
    return redirect('user_list')


# ------------------ Client CRUD ------------------

def create_client(request):
    if request.method == 'POST':
        organization_id = request.POST.get('organization_id')
        name = request.POST.get('name')
        phone_number = request.POST.get('phone_number')
        email = request.POST.get('email')
        timezone = request.POST.get('timezone')
        website = request.POST.get('website')
        signed_date = request.POST.get('signed_date')
        tenure = request.POST.get('tenure')
        amount_paid = request.POST.get('amount_paid')
        point_of_contact_name = request.POST.get('point_of_contact_name')
        point_of_contact_number = request.POST.get('point_of_contact_number')

        if not (organization_id and name and phone_number and email and timezone):
            return HttpResponse("Error: All fields are required", status=400)

        organization = get_object_or_404(Organization, id=organization_id)

        client = Client.objects.create(
            organization=organization,
            name=name,
            phone_number=phone_number,
            email=email,
            timezone=timezone,
            website=website,
            signed_date=datetime.strptime(signed_date, '%Y-%m-%d'),
            tenure=int(tenure),
            amount_paid=float(amount_paid),
            point_of_contact_name=point_of_contact_name,
            point_of_contact_number=point_of_contact_number
        )
        return redirect('client_list')

    organizations = Organization.objects.all()
    return render(request, 'create_client.html', {'organizations': organizations})


def client_list(request):
    clients = Client.objects.all()
    return render(request, 'client_list.html', {'clients': clients})


def edit_client(request, client_id):
    client = get_object_or_404(Client, id=client_id)

    if request.method == 'POST':
        client.name = request.POST.get('name')
        client.phone_number = request.POST.get('phone_number')
        client.email = request.POST.get('email')
        client.timezone = request.POST.get('timezone')
        client.website = request.POST.get('website')
        client.signed_date = datetime.strptime(request.POST.get('signed_date'), '%Y-%m-%d')
        client.tenure = int(request.POST.get('tenure'))
        client.amount_paid = float(request.POST.get('amount_paid'))
        client.point_of_contact_name = request.POST.get('point_of_contact_name')
        client.point_of_contact_number = request.POST.get('point_of_contact_number')
        client.save()

        return redirect('client_list')

    organizations = Organization.objects.all()
    return render(request, 'edit_client.html', {'client': client, 'organizations': organizations})


def delete_client(request, client_id):
    client = get_object_or_404(Client, id=client_id)
    client.delete()
    return redirect('client_list')

# ------------------ SLA CRUD ------------------

# Create SLA
def create_sla(request):
    if request.method == 'POST':
        priority = request.POST.get('priority')
        time_limit_in_hours = request.POST.get('time_limit_in_hours')

        if not priority or not time_limit_in_hours:
            return HttpResponse("Error: All fields are required", status=400)

        try:
            time_limit_in_hours = int(time_limit_in_hours)
        except ValueError:
            return HttpResponse("Error: Invalid time limit", status=400)

        sla = SLA.objects.create(
            priority=priority,
            time_limit_in_hours=time_limit_in_hours
        )
        return redirect('sla_list')

    return render(request, 'create_sla.html')


# List all SLAs
def sla_list(request):
    slas = SLA.objects.all()
    return render(request, 'sla_list.html', {'slas': slas})


# Edit SLA
def edit_sla(request, sla_id):
    sla = get_object_or_404(SLA, id=sla_id)

    if request.method == 'POST':
        sla.priority = request.POST.get('priority')
        sla.time_limit_in_hours = request.POST.get('time_limit_in_hours')

        if not sla.priority or not sla.time_limit_in_hours:
            return HttpResponse("Error: All fields are required", status=400)

        try:
            sla.time_limit_in_hours = int(sla.time_limit_in_hours)
        except ValueError:
            return HttpResponse("Error: Invalid time limit", status=400)

        sla.save()
        return redirect('sla_list')

    return render(request, 'edit_sla.html', {'sla': sla})


# Delete SLA
def delete_sla(request, sla_id):
    sla = get_object_or_404(SLA, id=sla_id)
    sla.delete()
    return redirect('sla_list')

#----------------------------------- ticket ---------------------------------------#

def list_ticket(request):
    tickets = Ticket.objects.all()
    return render(request, 'ticket_list.html',{'tickets': tickets})

def ticket_list(request):
    tickets = Ticket.objects.all()

    # Render the ticket list template with all tickets
    return render(request, 'ticket_list.html', {'tickets': tickets})

# View to create a new ticket

def create_ticket(request):
    if request.method == 'POST':
        form = TicketForm(request.POST, user=request.user)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.created_by = request.user  # Optionally save the user who created the ticket
            ticket.save()
            return redirect('ticket_list')  # Redirect to the ticket list view
    else:
        form = TicketForm()  # Pass the current user to filter organizations and projects
    return render(request, 'create_ticket.html', {'form': form})


PREDEFINED_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", 
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", 
    "Collection", "Exfiltration", "Impact"
]
def fetch_attack_data(sha256):
    # Example: Replace with your actual API call or local data retrieval
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"

    payload = 'hash='+sha256
    headers = {
    'accept': 'application/json',
    'api-key': '',
    'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    dt = response.json()

    # Initialize a dictionary to store tactics and techniques
    tactics_dict = {tactic: [] for tactic in PREDEFINED_TACTICS}

    # Loop through each technique (TTP) in the response
    ttp = dt[0].get('mitre_attcks', [])
    for item in ttp:
        tactic_name = item.get('tactic')
        technique_id = item.get('attck_id')  # Use the 'attck_id' directly
        technique_name = item.get('technique')
        technique_url = item.get('attck_id_wiki')

        malicious_count = item['malicious_identifiers_count']
        suspicious_count = item['suspicious_identifiers_count']
        informative_count = item['informative_identifiers_count']

        if malicious_count > 0:
            score = 3  # Malicious identifiers -> high severity
        elif suspicious_count > 0:
            score = 2  # Suspicious identifiers -> medium severity
        elif informative_count > 0:
            score = 1  # Informative identifiers -> low severity
        else:
            score = 0  # No identifiers -> lowest priority

        # Create the technique data dictionary
        technique_data = {
            "id": technique_id,
            "name": technique_name,
            "url": technique_url,
            "score": score
        }

        # Append the technique to the corresponding tactic in the dictionary
        if tactic_name in tactics_dict:
            tactics_dict[tactic_name].append(technique_data)

    # Render the matrix template and pass the tactics_dict
    return tactics_dict

def attack_matrix(request):
    sha256 = ""
    techniques = fetch_attack_data(sha256)
    # print("====tech dt===",techniques)
    
    return render(request, 'attack_matrix.html', {'tactics_dict': techniques})

client = pymongo.MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB URI if necessary
db = client["case_data"]  # Your database name
hash_collection = db["hash_value"]

# VirusTotal API Key (Replace with your actual key)
VIRUSTOTAL_API_KEY = ""

URLSCAN_API_KEY = ""

# Function to query VirusTotal for SHA256
def query_virustotal(sha256):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        
        return response.json()
    return None

# Function to query URLScan.io for domains
def query_urlscan(domain):
    headers = {"API-Key": URLSCAN_API_KEY}
    url = "https://urlscan.io/api/v1/search/"
    params = {"q": f"domain:{domain}"}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    return None

# Function to fetch reputation data
def get_reputation(alert_type, alert_value):
    document = hash_collection.find_one({alert_type: alert_value})

    if document:
        print("MongoDB Data Found:", document.get('reputation', 'Unknown'))
        return document.get('reputation', 'Unknown'), document.get('analysis_stats', {})

    else:
        print(f"{alert_type} not found in MongoDB. Querying external API...")
        
        if alert_type == "sha256":
            vt_data = query_virustotal(alert_value)
            if vt_data:
                reputation = vt_data.get('data', {}).get('attributes', {}).get('reputation', 'Unknown')
                analysis_stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                # Store in MongoDB
                hash_collection.insert_one({
                    "sha256": alert_value,
                    "reputation": reputation,
                    "analysis_stats": analysis_stats
                })
                return reputation, analysis_stats

        elif alert_type == "domain":
            urlscan_data = query_urlscan(alert_value)
            if urlscan_data and "results" in urlscan_data:
                reputation = "Suspicious" if any("malicious" in r.get("task", {}).get("tags", []) for r in urlscan_data["results"]) else "Clean"
                
                # Store in MongoDB
                hash_collection.insert_one({
                    "domain": alert_value,
                    "reputation": reputation
                })
                return reputation, {}

    return None, None
APT_SOURCES = [
    {"name": "ThreatFox", "url": "https://threatfox-api.abuse.ch/api/v1/", "payload": {"query": "search_hash", "api_key": os.getenv("THREATFOX_API_KEY")}},
    {"name": "MalwareBazaar", "url": "https://mb-api.abuse.ch/api/v1/", "payload": "query=get_info&hash={hash_value}"},
    {"name": "MISP", "url": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"}
]
def filter_apt_data(source_name, data):
    if source_name == "ThreatFox":
        return [
            {
                "malware": entry.get("malware"),
                "confidence": entry.get("confidence_level"),
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen")
            }
            for entry in data.get("data", []) if isinstance(entry, dict)
        ]
    elif source_name == "MalwareBazaar":
        malware_data = data.get("data", [])
        if not isinstance(malware_data, list) or not malware_data:
            return {}

        entry = malware_data[0] if isinstance(malware_data[0], dict) else {}

        return {
            "file_type": entry.get("file_type"),
            "file_name": entry.get("file_name"),
            "reporter": entry.get("reporter"),
            "signature": entry.get("signature"),
            "tags": entry.get("tags")
        }
    elif source_name == "MISP":
        return [
            {
                "name": actor.get("value"),
                "aliases": actor.get("meta", {}).get("synonyms", []),
                "country": actor.get("meta", {}).get("country", "Unknown"),
                "references": actor.get("meta", {}).get("refs", [])
            }
            for actor in data.get("values", []) if isinstance(actor, dict)
        ]
    return {}

def get_apt_intelligence(hash_value):
    results = {"hash": hash_value, "APT_mapping": {}}
    
    for source in APT_SOURCES:
        try:
            if source["name"] == "MISP":
                # MISP uses GET requests
                response = requests.get(source["url"], timeout=10)
            else:
                # Other sources use POST requests
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                
                # Ensure payload is a dictionary
                payload = source.get("payload", {})
                if isinstance(payload, dict):
                    payload = payload.copy()  # Create a copy to modify
                else:
                    payload = {}

                payload["hash"] = hash_value
                response = requests.post(source["url"], headers=headers, data=payload, timeout=10)

            # Process response
            if response.status_code == 200:
                try:
                    data = response.json()
                    results["APT_mapping"][source["name"]] = filter_apt_data(source["name"], data)
                except json.JSONDecodeError:
                    results["APT_mapping"][source["name"]] = "Invalid JSON response"
            else:
                results["APT_mapping"][source["name"]] = f"Error: HTTP {response.status_code}"

        except requests.Timeout:
            results["APT_mapping"][source["name"]] = "Request timed out"
        except requests.ConnectionError:
            results["APT_mapping"][source["name"]] = "Connection error"
        except requests.RequestException as e:
            results["APT_mapping"][source["name"]] = f"Request failed: {str(e)}"
    
    return results

def ticket_description(request, ticket_id):
    print("Fetching Ticket Details...")
    ticket = get_object_or_404(Ticket, id=ticket_id)
    matches = re.findall(r"([A-Za-z0-9\s]+):\s*([\S ]+)", ticket.description)

    # Format for frontend display
    formatted_description = "<br>".join([f"<strong>{key}:</strong> {value}" for key, value in matches])
    
    
    # print("Matches:", matches)
    # print("Formatted Description:", formatted_description)

    # Extract the file path and file name
    file_path = next((value for key, value in matches if key.strip() == "File Path"), None)
    file_name = os.path.basename(file_path) if file_path else None

    print("Extracted File Name:", file_name)
    # Print the formatted description and the extracted file name
    print("Formatted Description:", formatted_description)
    print("---=============-------")
    print("Extracted File Name:", file_name)
    # Regular expressions for SHA256 and domain
    sha256_pattern = r"SHA256\s*:\s*([a-fA-F0-9]{64})"
    domain_pattern = r"Domain\s*:\s*([\w\.]+)"

    description = ticket.description
    sha256_matches = re.findall(sha256_pattern, description)
    domain_matches = re.findall(domain_pattern, description)

    alert_type = None
    alert_value = None
    reputation = None
    analysis_stats = {}

    if sha256_matches:
        alert_type = 'sha256'
        alert_value = sha256_matches[0]
    elif domain_matches:
        alert_type = 'domain'
        alert_value = domain_matches[0]

    if alert_type and alert_value:
        reputation, analysis_stats = get_reputation(alert_type, alert_value)

    print('alert_type:', alert_type)
    print('alert_value:', alert_value)
    print('reputation:', reputation)
    ############################### open ai ####################
    os.environ["GITHUB_TOKEN"] = ""
    
    client = OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=os.environ["GITHUB_TOKEN"],
    )

    response = client.chat.completions.create(
        messages=[
            {
                "role": "system",
                "content": "",
            },
            {
                "role": "user",
                "content": "What this " + file_name + "file do?",
            }
        ],
        model="gpt-4o",
        temperature=1,
        max_tokens=4096,
        top_p=1
    )
    open_ai_resp = response.choices[0].message.content
    # print("####====",open_ai_resp)
    ############################## end of open ai #################

    ############################ Fetch ATT&CK TTPs ####################################
    # techniques = fetch_attack_data(alert_value)  # Assuming you have this function implemented

    ################################## Fetch APT Intelligence #######################
    # results = None
    # chart_labels = []
    # chart_data = []
    results = get_apt_intelligence(alert_value)

    #     # Processing data for visualization
    # if results and "APT_mapping" in results:
    #     chart_labels = list(results["APT_mapping"].keys())
    #     chart_data = [len(results["APT_mapping"][source]) if isinstance(results["APT_mapping"][source], list) else 0 for source in chart_labels]

    ##############################################################
    if request.method == 'POST':
        if request.headers.get('Content-Type') == 'application/json':
            # Handle AJAX request for status and assignee update
            data = json.loads(request.body)
            field = data.get('field')
            value = data.get('value')

            # Update ticket status
            if field == 'status':
                ticket.status = value

            # Update ticket assignee
            elif field == 'assignee':
                ticket.assignee_id = value if value else None

            ticket.save()
            return JsonResponse({'success': True})

        elif 'comment' in request.POST:
            comment_form = CommentForm(request.POST)
            print("New Comment:", comment_form)
            if comment_form.is_valid():
                comment = comment_form.save(commit=False)
                comment.ticket = ticket
                comment.user = request.user
                comment.save()

                # Return new comment as JSON
                comment_data = {
                    'user': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                }
                return JsonResponse({'success': True, 'comment': comment_data})
            else:
                return JsonResponse({'success': False, 'error': 'Invalid form data'})

    form = UpdateTicketForm(instance=ticket)
    comment_form = CommentForm()
    comments = ticket.comments.all()
    users = User.objects.all()

    return render(request, 'description.html', {
        'ticket': ticket,
        'formatted_description': formatted_description,
        'form': form,
        'comment_form': comment_form,
        'comments': comments,
        'users': users,
        'alert_type': alert_type,
        'alert_value': alert_value,
        # 'tactics_dict': techniques,
        'reputation': reputation,
        'open_ai_resp':open_ai_resp,
        'results': results,
        "misp_json": json.dumps(results["APT_mapping"].get("MISP", []))
        # 'chart_labels': json.dumps(chart_labels),
        # 'chart_data': json.dumps(chart_data)
    })

# def ticket_description(request, ticket_id):
#     # os.environ["GITHUB_TOKEN"] = ""
    
#     # client = OpenAI(
#     #     base_url="https://models.inference.ai.azure.com",
#     #     api_key=os.environ["GITHUB_TOKEN"],
#     # )

#     # response = client.chat.completions.create(
#     #     messages=[
#     #         {
#     #             "role": "system",
#     #             "content": "",
#     #         },
#     #         {
#     #             "role": "user",
#     #             "content": "What this blackbasta.exe file do?",
#     #         }
#     #     ],
#     #     model="gpt-4o",
#     #     temperature=1,
#     #     max_tokens=4096,
#     #     top_p=1
#     # )

#     # print(response.choices[0].message.content)
#     ###################################### mongo db ########################
#     client = pymongo.MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB URI if necessary
#     db = client["case_data"]  # Your database name
#     hash_collection = db["hash_value"]
#     #####################################################

   
#     print("testin-======")
#     ticket = get_object_or_404(Ticket, id=ticket_id)
#     formatted_description = ticket.description.replace(',', ',<br>')
#     ################################################################
#     sha256_pattern = r"SHA256\s*:\s*([a-fA-F0-9]{64})"
#     domain_pattern = r"Domain\s*:\s*([\w\.]+)"
#     description = ticket.description
#     # Regular expressions to find SHA256 and domain in the description
#     sha256_matches = re.findall(sha256_pattern, description)
#     domain_matches = re.findall(domain_pattern, description)

#     # Initialize alert_type and alert_value to None
#     alert_type = None
#     alert_value = None

#     if sha256_matches:
#         # If SHA256 found, set alert_type and alert_value
#         alert_type = 'sha256'
#         alert_value = sha256_matches[0]  # Use the first SHA256 hash found
#         document = hash_collection.find_one({"sha256": alert_value})
#         reputation = document['reputation']
#         print("mongodb doc====",document['reputation'])
#         print("mongodb doc====",document['analysis_stats'])
         
#     elif domain_matches:
#         # If domain found, set alert_type and alert_value
#         alert_type = 'domain'
#         alert_value = domain_matches[0]  # Use the first domain found
    
#     print('alert_type====', alert_type,
#         'alert_value=====', alert_value,)
    
#     ############################ ttps ####################################
#     techniques = fetch_attack_data(alert_value)

#     ##############################################################
#     if request.method == 'POST':
#         if request.headers.get('Content-Type') == 'application/json':
#             # Handle AJAX request for status and assignee update
#             data = json.loads(request.body)
#             field = data.get('field')
#             value = data.get('value')

#             # Update ticket status
#             if field == 'status':
#                 ticket.status = value

#             # Update ticket assignee
#             elif field == 'assignee':
#                 ticket.assignee_id = value if value else None

#             ticket.save()
#             return JsonResponse({'success': True})
    
#         elif 'comment' in request.POST:
#             comment_form = CommentForm(request.POST)
#             print("comm=======",comment_form)
#             if comment_form.is_valid():
#                 comment = comment_form.save(commit=False)
#                 comment.ticket = ticket
#                 comment.user = request.user
#                 comment.save()
                

#                 # If the request is AJAX, return the new comment as JSON
                
#                 comment_data = {
#                     'user': comment.user.username,
#                     'content': comment.content,
#                     'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#                 }
#                 return JsonResponse({'success': True, 'comment': comment_data})
#             else:
#                 # If form is invalid, return error
#                 return JsonResponse({'success': False, 'error': 'Invalid form data'})
        
#     form = UpdateTicketForm(instance=ticket)
#     comment_form = CommentForm()
#     comments = ticket.comments.all()
#     users = User.objects.all() 
#     return render(request, 'description.html', {
#         'ticket': ticket,
#         'formatted_description': formatted_description,
#         'form': form,
#         'comment_form': comment_form,
#         'comments': comments,
#         'users': users,
#         'alert_type': alert_type,
#         'alert_value': alert_value,
#         'tactics_dict': techniques,
#         'reputation':reputation
#     })



def update_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    
    # Initialize the forms
    form = None
    comment_form = None

    if request.method == 'POST':
        if 'comment' in request.POST:  # If the comment form is submitted
            comment_form = CommentForm(request.POST)
            if comment_form.is_valid():
                comment = comment_form.save(commit=False)
                comment.ticket = ticket
                comment.user = request.user  # The user who is commenting
                comment.save()
        else:  # Otherwise, handle the ticket update form submission (assignee, title, description, etc.)
            form = UpdateTicketForm(request.POST, instance=ticket)
            if form.is_valid():
                form.save()  # Save the updated ticket with the new assignee if changed
                return redirect('ticket_list')  # Redirect to the ticket list after saving
    else:
        # For GET request, initialize both forms
        form = UpdateTicketForm(instance=ticket)
        comment_form = CommentForm()  # Form to add a new comment
    
    # Fetch existing comments for the ticket
    comments = ticket.comments.all()

    return render(request, 'update_ticket.html', {
        'form': form,
        'ticket': ticket,
        'comment_form': comment_form,
        'comments': comments,
    })

