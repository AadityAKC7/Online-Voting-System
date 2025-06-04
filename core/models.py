from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings




class Position(models.Model):
    name = models.CharField(max_length=100)
    max_votes = models.PositiveIntegerField()
    priority = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} "


class Candidate(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='candidate_images/', default='candidate_images/default.jpg')
    position = models.ForeignKey(Position, on_delete=models.CASCADE, related_name='candidates')
    votes = models.IntegerField(default=0)
    priority = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.position.name})"


class Vote(models.Model):
    voter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE)
    position = models.ForeignKey(Position, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Ensure voter can only vote once per position
        unique_together = ('voter', 'position')

    def __str__(self):
        return f"{self.voter.email} voted for {self.candidate.name}"


class VoterManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class Voter(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', default='profile_pics/default.jpg')
    phone = models.CharField(max_length=10, unique=True)
    national_id = models.CharField(max_length=20, unique=True, null=True, blank=True)
    has_voted = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone']

    objects = VoterManager()

    def __str__(self):
        return self.email
