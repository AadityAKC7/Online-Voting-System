from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
from django.http import HttpResponse
import logging
from core.utils import decrypt_rsa
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import random
import os
from django.db import IntegrityError
from django.contrib import messages

from .models import (
    Candidate,
    Vote,
    Voter,
    Position,
)
from .forms import (
    RegisterForm,
    SimpleLoginForm,
    VoterEditForm,
    CandidateForm,
    PositionForm,
    VoterForm,
)


User = get_user_model()

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.username = form.cleaned_data['email']  # optional if using email as username
            user.save()
            login(request, user)  # auto login after register
            return redirect('dashboard')  # change to your post-login page
    else:
        form = RegisterForm()
    return render(request, 'registration/register.html', {'form': form})

def simple_login_view(request):
    if request.method == 'POST':
        form = SimpleLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            try:
                user_obj = User.objects.get(email=email)
                user = authenticate(request, username=email, password=password)
                if user is not None:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    form.add_error(None, "Invalid email or password")
            except User.DoesNotExist:
                form.add_error(None, "Invalid email or password")
    else:
        form = SimpleLoginForm()
    return render(request, 'registration/simple_login.html', {'form': form})

@login_required
def dashboard(request):
    # Redirect admin users to admin panel or custom admin dashboard
    if request.user.is_superuser or request.user.is_staff:
        return redirect('/admin-dashboard/')  # or: return redirect('admin_dashboard')

    # Regular user logic
    already_voted = Vote.objects.filter(voter=request.user).exists()
    candidates = Candidate.objects.all() if not already_voted else []

    return render(request, 'dashboard.html', {
        'already_voted': already_voted,
        'candidates': candidates,
    })

@login_required
def edit_profile_pic(request):
    if request.method == 'POST':
        profile_pic = request.FILES.get('profile_pic')
        if profile_pic:
            request.user.profile_pic = profile_pic
            request.user.save()
    return redirect('dashboard')

def vote_page(request):
    return render(request, 'vote.html')  # adjust template name as needed

@login_required
def edit_profile(request):
    user = request.user
    if request.method == 'POST':
        form = VoterEditForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('dashboard')  # or any page you want after editing
    else:
        form = VoterEditForm(instance=user)
    return render(request, 'edit_profile.html', {'form': form})
def generate_otp():
    return str(random.randint(100000, 999999))

def verify_email_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = generate_otp()
        request.session['email_to_verify'] = email
        request.session['otp'] = otp

        subject = 'Your OTP for Email Verification'
        message = f'Your OTP code is: {otp}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, f"OTP sent to {email}. Please check your inbox.")
        except Exception as e:
            messages.error(request, f"Failed to send OTP email: {str(e)}")
            return render(request, 'verify_email.html')

        return redirect('verify_otp')

    return render(request, 'verify_email.html')


def verify_otp_view(request):
    if request.method == 'POST':
        input_otp = request.POST.get('otp')
        session_otp = request.session.get('otp')
        email = request.session.get('email_to_verify')

        if input_otp == session_otp:
            user = Voter.objects.get(email=email)
            user.is_email_verified = True
            user.save()

            login(request, user)  # Refresh session with updated user

            messages.success(request, "Email verified successfully!")
            request.session.pop('otp', None)
            request.session.pop('email_to_verify', None)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid OTP. Try again.")

    return render(request, 'verify_otp.html')

def notifications(request):
    return render(request, 'core/notifications.html')

def search(request):
    query = request.GET.get('q', '')
    return render(request, 'core/search_results.html', {'query': query})


logger = logging.getLogger(__name__)

def decrypt_rsa(encrypted_base64: str) -> str:
    private_key_path = os.path.join(settings.BASE_DIR, 'core', 'keys', 'private_key.pem')
    
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # If your key is encrypted, provide the password here
            backend=default_backend()
        )

    encrypted_bytes = base64.b64decode(encrypted_base64)

    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.PKCS1v15()
    )

    return decrypted.decode('utf-8')




@staff_member_required
def admin_required(view_func):
    return user_passes_test(lambda u: u.is_superuser)(view_func)
@staff_member_required
def admin_dashboard(request):
    positions = Position.objects.all()
    vote_data = []

    for pos in positions:
        candidates = Candidate.objects.filter(position=pos)
        labels = []
        data = []
        voters_per_candidate = []
        zipped = []

        for cand in candidates:
            labels.append(cand.name)
            votes = Vote.objects.filter(candidate=cand)
            data.append(votes.count())
            voter_names = [f"{vote.voter.first_name} {vote.voter.last_name}" for vote in votes]
            voters_per_candidate.append(voter_names)
            zipped.append((cand.name, voter_names))

        vote_data.append({
            'position': pos.name,
            'labels': labels,
            'data': data,
            'zipped': zipped
        })

    context = {
        'vote_data': vote_data,
        'num_positions': Position.objects.count(),
        'num_candidates': Candidate.objects.count(),
        'total_voters': Voter.objects.count(),
        'voters_voted': Vote.objects.values('voter').distinct().count(),
    }

    return render(request, 'admin-dashboard.html', context)

def get_public_key(request):
    public_key_path = os.path.join(settings.BASE_DIR, "core", "keys", "public_key.pem")
    with open(public_key_path, "rb") as f:
        public_key = f.read()
    return HttpResponse(public_key, content_type="text/plain")

@staff_member_required
def votes(request):
    if request.method == 'POST':
        Candidate.objects.update(votes=0)
        Voter.objects.update(has_voted=False)
        Vote.objects.all().delete()
        messages.success(request, "All votes have been reset.")
        return redirect('admin-dashboard')
    
    votes = Vote.objects.select_related('voter', 'candidate__position').all()
    return render(request, 'admin/votes.html', {'votes': votes})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def reset_votes(request):
    if request.method == 'POST':
        Vote.objects.all().delete()
        messages.success(request, "All votes have been reset.")
    return redirect('votes')

@staff_member_required
def manage_voters(request):
    voters = Voter.objects.all()
    return render(request, 'admin/manage_voters.html', {'voters': voters})

def edit_voter(request):
    if request.method == "POST":
        voter_id = request.POST.get('voter_id')
        voter = get_object_or_404(Voter, pk=voter_id)

        voter.first_name = request.POST.get('first_name')
        voter.last_name = request.POST.get('last_name')
        voter.email = request.POST.get('email')
        voter.phone = request.POST.get('phone')
        voter.national_id = request.POST.get('national_id')

        password = request.POST.get('password')
        if password:
            # Save hashed password
            voter.password = make_password(password)

        voter.save()
        messages.success(request, 'Voter details updated successfully.')
        return redirect('manage_voters')

    # fallback redirect
    return redirect('manage_voters')

@require_POST
def delete_voter(request, voter_id):
    voter = get_object_or_404(Voter, pk=voter_id)
    voter.delete()
    messages.success(request, "Voter deleted successfully.")
    return redirect('manage_voters')


logger = logging.getLogger(__name__)

@login_required
def decryptw(request):
    if not request.user.is_email_verified:
        return redirect('verify_email')

    if request.method == 'POST':
        voter = request.user
        encrypted_data = request.POST.get('encrypted_vote')

        if not encrypted_data:
            messages.error(request, "No vote data received.")
            return redirect('vote')

        try:
            decrypted = decrypt_rsa(encrypted_data)
            logger.debug(f"Decrypted payload: {decrypted}")
            payload = json.loads(decrypted)

            if payload.get('national_id') != voter.national_id:
                messages.error(request, "Voter ID mismatch.")
                return redirect('vote')

            votes = payload.get('votes', {})

            # Check votes is a dict and not empty
            if not isinstance(votes, dict) or not votes:
                messages.error(request, "No votes found in payload.")
                return redirect('vote')

            for position_id, candidate_id in votes.items():
                position = get_object_or_404(Position, id=position_id)
                candidate = get_object_or_404(Candidate, id=candidate_id, position=position)

                if Vote.objects.filter(voter=voter, position=position).exists():
                    continue  # Already voted for this position

                candidate.votes += 1
                candidate.save()

                Vote.objects.create(voter=voter, candidate=candidate, position=position)

            voter.has_voted = True
            voter.save()

            messages.success(request, "Your votes have been submitted successfully.")
            return redirect('dashboard')

        except Exception as e:
            logger.error(f"Vote submission error: {e}", exc_info=True)
            messages.error(request, f"Vote failed: {e}")
            return redirect('vote')

    positions = Position.objects.all()
    candidates_by_position = {position: Candidate.objects.filter(position=position) for position in positions}
    return render(request, 'vote.html', {'candidates_by_position': candidates_by_position})


@staff_member_required
def manage_candidates(request):
    if request.method == 'POST':
        form = CandidateForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('manage_candidates')
    else:
        form = CandidateForm()

    candidates = Candidate.objects.select_related('position').all()
    return render(request, 'admin/manage_candidates.html', {
        'form': form,
        'candidates': candidates,
    })


def add_candidate(request):
    if request.method == 'POST':
        form = CandidateForm(request.POST, request.FILES)  # Correct: include request.FILES
        if form.is_valid():
            form.save()
            return redirect('manage_candidates')  # <-- fix to 'manage_candidates' if that is your URL name
    else:
        form = CandidateForm()
    return render(request, 'admin/candidate_form.html', {'form': form, 'title': 'Add Candidate'})



def edit_candidate(request, pk):
    candidate = get_object_or_404(Candidate, pk=pk)
    if request.method == 'POST':
        form = CandidateForm(request.POST, request.FILES, instance=candidate)
        if form.is_valid():
            form.save()
            return redirect('manage_candidates')
    else:
        form = CandidateForm(instance=candidate)
    return render(request, 'admin/candidate_form.html', {'form': form, 'title': 'Edit Candidate'})

def delete_candidate(request, pk):
    candidate = get_object_or_404(Candidate, pk=pk)
    candidate.delete()
    return redirect('manage_candidates')

@staff_member_required
def manage_positions(request):
    if request.method == 'POST':
        form = PositionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('manage_positions')
    else:
        form = PositionForm()

    positions = Position.objects.all()
    return render(request, 'admin/manage_positions.html', {
        'form': form,
        'positions': positions
    })

@staff_member_required
def edit_position(request, pk):
    position = get_object_or_404(Position, pk=pk)
    if request.method == 'POST':
        form = PositionForm(request.POST, instance=position)
        if form.is_valid():
            form.save()
            return redirect('manage_positions')
    else:
        form = PositionForm(instance=position)
    return render(request, 'admin/position_form.html', {'form': form, 'title': 'Edit Position'})

@staff_member_required
def delete_position(request, pk):
    position = get_object_or_404(Position, pk=pk)
    position.delete()
    return redirect('manage_positions')


@staff_member_required
def candidate_management(request):
    if request.method == 'POST':
        form = CandidateForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('candidate_management')
    else:
        form = CandidateForm()

    candidates = Candidate.objects.all().order_by('priority')
    return render(request, 'admin/manage_candidates.html', {'candidates': candidates, 'form': form})

@login_required
@user_passes_test(lambda u: u.is_superuser)
def all_votes_view(request):
    votes = Vote.objects.select_related('voter', 'candidate__position').all()
    return render(request, 'votes.html', {'votes': votes})

