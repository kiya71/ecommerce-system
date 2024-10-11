from django.shortcuts import render,redirect
from .forms import RegistrationForm
from .models import Account
from django.http import HttpResponse
from django.contrib import messages,auth
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required


#verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from carts.views import _cart_id
from carts.models import Cart, CartItem
import requests

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']
            username=email.split('@')[0]
            user=Account.objects.create_user(first_name=first_name, last_name=last_name, email=email,username=username,password=password)
            user.phone_number = phone_number
            user.save()

            #Account activation
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('accounts/account_activation_email.html', {
                'user':user,
                'domain':current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),
            })
            to_email = email
            send_mail=EmailMessage(mail_subject, message, to=[to_email])
            send_mail.send()
            #messages.success(request,'Thank you for registering with us. we have sent you an email verification link')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {'form': form}
    return render(request, 'accounts/register.html', context)




def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(email=email, password=password)
        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists=CartItem.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_item=CartItem.objects.filter(cart=cart)
                    #getting product variation by cart id
                    product_variation=[]
                    for item in cart_item:
                       variation=item.variations.all()
                       product_variation.append(list(variation))

              #getting cart items from  the user access to his product variations
                cart_items = CartItem.objects.filter(user=user)
                ex_var_list = []
                id_list = []

                for item in cart_items:
                    existing_variation = item.variations.all()
                    ex_var_list.append(list(existing_variation))
                    id_list.append(item.id)



                for pr in product_variation:
                     if pr in ex_var_list:
                        index = ex_var_list.index(pr)
                        item_id=id_list[index]
                        item=CartItem.objects.get(id=item_id)
                        item.quantity=+1
                        item.user=user
                        item.save()
                     else:
                         cart_item=CartItem.objects.filter(cart=cart)
                         for item in cart_item:
                             item.user=user
                             item.save()






            except:
                pass
            auth.login(request, user)
            messages.success(request, 'You are now logged in!')
            url=request.META['HTTP_REFERER']
            try:
                query=requests.utils.urlparse(url).query
                params=dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage=params['next']
                    return redirect(nextPage)
            except:
                pass
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid email or password.')
            return redirect('login')
    return render(request, 'accounts/login.html')



@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')

@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            #reset Password
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password.'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_mail = EmailMessage(mail_subject, message, to=[to_email])
            send_mail.send()

            messages.success(request, 'Password reset email has been sent to your email address.')
            return redirect('login')

        else:
            messages.error(request, 'Account does not exist!.')
            return redirect('forgot_password')

    return render(request, 'accounts/forgot_password.html')







def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account has been activated.')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link.')
        return redirect('register')


def reset_password_vaildate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)

    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = user.id
        messages.success(request, 'Please, reset your password.')
        return redirect('resetPassword')
    else:
        messages.error(request, 'The link has been expired.')
        return redirect('login')


def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            uid=request.session['uid']
            user = Account._default_manager.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Your password has been reset.')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('resetPassword')
    else:
        return render(request, 'accounts/resetPassword.html')

