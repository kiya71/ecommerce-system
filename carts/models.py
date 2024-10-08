from django.db import models
from store.models import Product,Variation


class Cart(models.Model):
    cart_id = models.CharField(max_length=100,blank=True)
    date_added = models.DateField(auto_now_add=True)




    def __str__(self):
        return self.cart_id

class CartItem(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)
    variations = models.ManyToManyField(Variation, blank=True)
    quantity = models.IntegerField(default=1)
    is_active = models.BooleanField(default=True)


    def __unicode__(self):
        return self.product

    def sub_total(self):
        return self.product.price*self.quantity
