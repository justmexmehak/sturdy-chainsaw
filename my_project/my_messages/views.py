from django.shortcuts import render

# Create your views here.

from .models import Message
from .serializers import MessageSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from django.core.mail import send_mail

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse

from rest_framework.permissions import IsAuthenticated


class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # Authenticate the user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Log the user in
            login(request, user)
            return JsonResponse({"message": "Login successful"}, status=200)
        else:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

class LogoutView(APIView):
    def post(self, request):
        # Log the user out
        logout(request)
        return JsonResponse({"message": "Logout successful"}, status=200)



class MessageList(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated
    def get(self, request):
        messages = Message.objects.all()
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            message = serializer.save()
            # Send an email to the user
            send_mail(
                subject="New Message Posted",
                message=f"Your message '{message.content}' has been successfully posted.",
                from_email="mehaknauman6@gmail.com",  # Replace with your email
                recipient_list=["mehaknauman6@gmail.com"],  # Assuming the Message model has a user field
                fail_silently=False,
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
