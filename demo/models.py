from django.db import models

# Create your models here.
from django.db import models
from cryptography.hazmat.primitives.asymmetric import rsa


class Nodes(models.Model):
    node = models.URLField(unique=True,primary_key=True)

    def __str__(self):
        return self.node


class Block(models.Model):
    index = models.IntegerField()
    timestamp = models.CharField(max_length=255)
    proof = models.IntegerField()
    previous_hash = models.CharField(max_length=256)
    # Add other fields as needed for your transactions
    transactions = models.ManyToManyField('Transaction')


class Transaction(models.Model):
    sender = models.CharField(max_length=255)
    recipient = models.CharField(max_length=255)
    amount = models.IntegerField()
    signature = models.BinaryField()


class Key(models.Model):
    public_key = models.TextField(null=True, blank=True)
    private_key = models.TextField(null=True, blank=True)

