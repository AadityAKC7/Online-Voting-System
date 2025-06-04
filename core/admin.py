from django.contrib import admin
from .models import Voter, Candidate, Position, Vote

@admin.register(Voter)
class VoterAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'phone', 'is_email_verified', 'is_active', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name', 'phone')
    list_filter = ('is_email_verified', 'is_active', 'is_staff')

@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('name', 'position', 'votes', 'priority', 'created_at')
    search_fields = ('name',)
    list_filter = ('position',)

@admin.register(Position)
class PositionAdmin(admin.ModelAdmin):
    list_display = ('name', 'max_votes', 'priority', 'created_at')
    search_fields = ('name',)
    ordering = ('priority',)

@admin.register(Vote)
class VoteAdmin(admin.ModelAdmin):
    list_display = ('voter', 'candidate', 'position', 'timestamp')
    list_filter = ('position', 'timestamp')
    search_fields = ('voter__email', 'candidate__name')
