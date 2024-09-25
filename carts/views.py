from django.shortcuts import render,redirect,get_object_or_404
from store.models import Product,Variation
from .models import Cart, CartItem
from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist



def _cart_id(request):
    cart = request.session.session_key
    if not cart:
        cart = request.session.create()
    return cart

def add_cart(request, product_id):
    product = Product.objects.get(id=product_id)
    product_variation = []

    if request.method == 'POST':
        color = request.POST.get('color')
        size = request.POST.get('size')

        # Check for color and size variations in POST data
        if color:
            try:
                color_variation = Variation.objects.get(
                    product=product,
                    variation_category__iexact='color',
                    variation_value__iexact=color
                )
                product_variation.append(color_variation)
            except Variation.DoesNotExist:
                pass

        if size:
            try:
                size_variation = Variation.objects.get(
                    product=product,
                    variation_category__iexact='size',
                    variation_value__iexact=size
                )
                product_variation.append(size_variation)
            except Variation.DoesNotExist:
                pass

    # Retrieve or create a cart
    try:
        cart = Cart.objects.get(cart_id=_cart_id(request))
    except Cart.DoesNotExist:
        cart = Cart.objects.create(cart_id=_cart_id(request))
        cart.save()

    # Check if the cart item already exists
    is_cart_item_exists = CartItem.objects.filter(product=product, cart=cart).exists()

    if is_cart_item_exists:
        cart_items = CartItem.objects.filter(product=product, cart=cart)
        ex_var_list = []
        id_list = []

        for item in cart_items:
            existing_variation = item.variations.all()
            ex_var_list.append(list(existing_variation))
            id_list.append(item.id)

        if product_variation in ex_var_list:
            index = ex_var_list.index(product_variation)
            item_id = id_list[index]
            item = CartItem.objects.get(id=item_id)
            item.quantity += 1
            item.save()
        else:
            # New variation, create a new cart item
            cart_item = CartItem.objects.create(product=product, quantity=1, cart=cart)
            if len(product_variation) > 0:
                cart_item.variations.add(*product_variation)
            cart_item.save()
    else:
        # If the cart item doesn't exist, create a new one
        cart_item = CartItem.objects.create(product=product, quantity=1, cart=cart)
        if len(product_variation) > 0:
            cart_item.variations.add(*product_variation)
        cart_item.save()

    return redirect('cart')

def remove_cart(request,product_id,cart_item_id):
    cart = Cart.objects.get(cart_id=_cart_id(request))
    product = get_object_or_404(Product, id=product_id)
    try:
        cart_item = CartItem.objects.get(product=product, cart=cart, id=cart_item_id)
        if cart_item.quantity > 1:
            cart_item.quantity -= 1
            cart_item.save()
        else:
            cart_item.delete()
    except:
        pass
    return redirect('cart')


def remove_cart_item(request,product_id,cart_item_id):
    cart=Cart.objects.get(cart_id=_cart_id(request))
    product = get_object_or_404(Product,id=product_id)
    cart_item = CartItem.objects.get(product=product, cart=cart, id=cart_item_id)
    cart_item.delete()
    return redirect('cart')

def cart(request,total=0, quantity=0, cart_items=None):
    try:
        tax=0
        grand_total=0
        cart = Cart.objects.get(cart_id=_cart_id(request))
        cart_items = CartItem.objects.filter(cart=cart,is_active=True)
        for cart_item in cart_items:
            total += (cart_item.product.price*cart_item.quantity)
            quantity += cart_item.quantity
        tax = (2 * total) / 100
        grand_total = total + tax
    except ObjectDoesNotExist:
        pass
    context = {
        'total': total,
        'quantity': quantity,
        'cart_items': cart_items,
        'tax': tax,
        'grand_total': grand_total,
    }
    return render(request,'store/cart.html', context )