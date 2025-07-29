from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from core import views as core_views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from core.views import get_public_key

urlpatterns = [

    # # Django built-in admin at /django-admin/ (change as you want)
    path('django-admin/', admin.site.urls),

    # Django built-in auth urls
    path('accounts/', include('django.contrib.auth.urls')),

    # Your app's custom URLs
    path('register/', core_views.register_view, name='register'),
    path('dashboard/', core_views.dashboard, name='dashboard'),
    path('login/', core_views.simple_login_view, name='login'),

    path('', RedirectView.as_view(url='/login/', permanent=False)),
    path('edit_profile_pic/', core_views.edit_profile_pic, name='edit_profile_pic'),
    path('verify-email/', core_views.verify_email_view, name='verify_email'),
    path('verify-email/otp/', core_views.verify_otp_view, name='verify_otp'),
    path('edit-profile/', core_views.edit_profile, name='edit_profile'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('notifications/', core_views.notifications, name='notifications'),
    path('get-public-key/', core_views.get_public_key, name='get_public_key'),

    path('search/', core_views.search, name='search'),
    path('vote/', core_views.decryptw, name='vote'),
    path('api/public-key/', get_public_key, name='get_public_key'),

    path('admin-dashboard/', core_views.admin_dashboard, name='admin_dashboard'),
    path('votes/', core_views.votes, name='votes'),
    path('manage-voters/', core_views.manage_voters, name='manage_voters'),
    path('manage-positions/', core_views.manage_positions, name='manage_positions'),
    path('manage-positions/edit/<int:pk>/', core_views.edit_position, name='edit_position'),
    path('manage-positions/delete/<int:pk>/', core_views.delete_position, name='delete_position'),
    path('edit-voter/', core_views.edit_voter, name='edit_voter'),
    path('delete-voter/<int:voter_id>/', core_views.delete_voter, name='delete_voter'),
    path('votes/reset/', core_views.reset_votes, name='reset_votes'),

    # Your custom admin-like views under /admin/ prefix
    path('admin/candidates/', core_views.manage_candidates, name='manage_candidates'),
    path('admin/candidates/add/', core_views.add_candidate, name='add_candidate'),
    path('admin/candidates/edit/<int:pk>/', core_views.edit_candidate, name='edit_candidate'),
    path('admin/candidates/delete/<int:pk>/', core_views.delete_candidate, name='delete_candidate'),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
