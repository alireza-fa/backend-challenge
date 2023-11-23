from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema
from django.core.validators import MinLengthValidator
from rest_framework_simplejwt.tokens import RefreshToken

from .models import BaseUser, Profile
from .selectors import get_profile
from .services import register
from .validators import number_validator, letter_validator, special_char_validator


class ProfileApi(APIView):
    permission_classes = (IsAuthenticated,)

    class OutputProfileSerializer(serializers.ModelSerializer):

        class Meta:
            model = Profile
            fields = ('bio', 'post_count', 'subscriber_count', 'subscription_count')

    @extend_schema(responses=OutputProfileSerializer)
    def get(self, request):
        query = get_profile(user=request.user)
        return Response(self.OutputProfileSerializer(instance=query, context={"request": request}).data)


class RegisterApi(APIView):

    class InputRegisterSerializer(serializers.Serializer):
        email = serializers.EmailField(max_length=255)
        bio = serializers.CharField(max_length=1000, required=False)
        password = serializers.CharField(
            validators=[
                number_validator,
                letter_validator,
                special_char_validator,
                MinLengthValidator(limit_value=10)
            ]
        )
        confirm_password = serializers.CharField(max_length=255)

        def validate_email(self, email):
            if BaseUser.objects.filter(email=email).exists():
                raise serializers.ValidationError('email Already Taken')
            return email

        def validate(self, attrs):
            if attrs.get('password') != attrs.get('confirm_password'):
                raise serializers.ValidationError('confirm password is not equal to password')
            return attrs

    class OutputRegisterSerializer(serializers.ModelSerializer):
        token = serializers.SerializerMethodField('get_token')

        class Meta:
            model = BaseUser
            fields = ('email', 'token', 'created_at', 'updated_at')

        def get_token(self, user):
            data = dict()
            token_class = RefreshToken

            refresh = token_class.for_user(user=user)

            data["refresh"] = str(refresh)
            data["access"] = str(refresh.access_token)

            return data

    @extend_schema(request=InputRegisterSerializer, responses=OutputRegisterSerializer)
    def post(self, request):
        serializer = self.InputRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = register(
                email=serializer.validated_data.get('email'),
                password=serializer.validated_data.get('password'),
                bio=serializer.validated_data.get('bio'),
            )
        except Exception as ex:
            return Response(
                f'Database Error {ex}',
                status=status.HTTP_400_BAD_REQUEST
            )
        return Response(self.OutputRegisterSerializer(instance=user).data, status=status.HTTP_200_OK)
