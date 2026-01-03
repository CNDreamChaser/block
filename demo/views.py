from django.shortcuts import render
# Create your views here.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json
import hashlib
import requests
from time import time
from uuid import uuid4
from urllib.parse import urlparse
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from demo.models import Nodes,Block, Transaction,Key
from django.http import JsonResponse
from django.forms.models import model_to_dict
from django.core.serializers.json import DjangoJSONEncoder
import base64


class CustomJSONEncoder(DjangoJSONEncoder):
    def default(self, obj):
        # Check if the object is a Transaction instance
        if isinstance(obj, Transaction):
            # Convert the Transaction object to a dictionary
            return model_to_dict(obj)
        return super().default(obj)
@csrf_exempt
def initialize_node(request):
    if request.method == 'POST':
        # 获取 JSON 数据，假设 JSON 数据中包含 "port" 字段
        try:
            json_data = json.loads(request.body.decode('utf-8'))
            current_port = json_data.get('port')
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        if current_port is not None:
            nodes = Nodes.objects.values_list('node', flat=True)
            if current_port not in nodes:
                node = Nodes(node=current_port)
                node.save()
            return JsonResponse({"message": "Node initialized successfully"})

    # 如果不是 POST 请求，可以返回适当的响应
    return JsonResponse({"error": "Invalid request method"}, status=405)



class Blockchain(object):
    def __init__(self):
        if Block.objects.exists():
            # 从数据库中加载现有的区块链
            self.chain = list(Block.objects.all().order_by('index'))
            self.node_key_pair = self.get_or_generate_key_pair()
            self.nodes = set(Nodes.objects.values_list('node', flat=True))
        else:
            self.chain = []
            self.current_transactions = []
            self.new_block(previous_hash=1, proof=100)
            self.nodes = set(Nodes.objects.values_list('node', flat=True))
            self.node_key_pair = self.get_or_generate_key_pair()

    def get_or_generate_key_pair(self):
        current_node = Key.objects.filter(id=1).first()
        if current_node:
            # Retrieve existing keys from the database
            private_key = serialization.load_pem_private_key(
                current_node.private_key.encode(),
                password=None,
                backend=default_backend()
            )
            public_key = serialization.load_pem_public_key(
                current_node.public_key.encode(),
                backend=default_backend()
            )
            return private_key, public_key
        else:
            # Generate a new key pair
            return self.generate_key_pair()

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Save the new keys to the database
        Key.objects.create(private_key=private_key_pem.decode('utf-8'), public_key=public_key_pem.decode('utf-8'))

        return private_key, public_key

    def new_block(self,proof,previous_hash=None):
        # Create a new Block and adds it to the chain
        self.chain = list(Block.objects.all().order_by('index'))
        block = Block.objects.create(
            index=len(self.chain) + 1,
            timestamp=str(time()),
            proof=proof,
            previous_hash=previous_hash or self.hash(self.chain[-1]),
        )
        self.chain = list(Block.objects.all().order_by('index'))
        return block

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
        :return: None
        """

        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        if not Nodes.objects.filter(node=parsed_url.netloc).exists():
            node = Nodes(node=parsed_url)
            node.save()

    def sign_transaction(self, transaction):
        private_key, _ = self.node_key_pair
        signature = private_key.sign(
            json.dumps(transaction, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature


    def new_transaction(self,sender,recipient,amount,chain_length):
        # Adds a new transactions to the list of transactions
        # 生成新交易信息，信息将加入到下一个待挖的区块中
        # : param sender: <str> Address of the Sender
        # : param recipient: <str> Address of the Recipient
        # : param amount: <int> Amount
        # : return: <int> The index of the Block that will hold this transactions

        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }
        signature = self.sign_transaction(transaction)
        transaction['signature'] = signature
        transaction = Transaction(sender=sender, recipient=recipient, amount=amount, signature=signature)
        transaction.save()
        '''Transaction.objects.create(

            sender=sender,
            recipient=recipient,
            amount=amount,
            signature=signature,
            # Add other fields as needed
        )
        '''
        self.chain[chain_length].transactions.add(transaction)


    def verify_transaction(self, transaction, received_public_key):
        #_, public_key = self.node_key_pair
        signature = transaction.get('signature', '')
        signature = base64.b64decode(signature)  # 将字符串解码为字节串
        transaction_simply = {
            'sender': transaction['sender'],
            'recipient':transaction['recipient'],
            'amount': transaction["amount"],
        }
        data_to_verify = json.dumps(transaction_simply, sort_keys=True).encode()
        received_public_key = serialization.load_pem_public_key(
            received_public_key.encode('utf-8'),
            backend=default_backend()
        )
        try:
            received_public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def hash(block):
        # Hashes a Block
        block_dict = model_to_dict(block,exclude=['id'])
        transactions_list = list(block.transactions.all())
        # 将模型实例转换为字典
        transactions_data = [
            {

                'sender': transaction.sender,
                'recipient': transaction.recipient,
                'amount': transaction.amount,
                'signature': base64.b64encode(transaction.signature).decode('utf-8')  # 将BinaryField转换为字符串
            }
            for transaction in transactions_list
        ]
        # 更新区块字典中的交易信息
        block_dict['transactions'] = transactions_data
        block_string = json.dumps(block_dict, sort_keys=True,cls=CustomJSONEncoder).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        # Return the last Block in the chain
        self.chain = list(Block.objects.all().order_by('index'))
        return self.chain[-1]

    def proof_of_work(self, last_block):
        proof = 0
        while self.valid_proof(last_block, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_block, proof):
        block_dict = model_to_dict(last_block,exclude=['id'])
        transactions_list = list(last_block.transactions.all())
        # 将模型实例转换为字典
        transactions_data = [
            {

                'sender': transaction.sender,
                'recipient': transaction.recipient,
                'amount': transaction.amount,
                'signature': base64.b64encode(transaction.signature).decode('utf-8')  # 将BinaryField转换为字符串
            }
            for transaction in transactions_list
        ]
        # 更新区块字典中的交易信息
        block_dict['transactions'] = transactions_data
        block_string = json.dumps(block_dict, sort_keys=True,cls=CustomJSONEncoder).encode()
        guess = block_string + str(proof).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"

    def valid_chain_hash(self,block):
        block_string = json.dumps(block, sort_keys=True,cls=CustomJSONEncoder).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def valid_chain_proof(last_block, proof):

        block_string = json.dumps(last_block, sort_keys=True,cls=CustomJSONEncoder).encode()
        guess = block_string + str(proof).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            print(last_block)
            print(block)
            print("\n----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.valid_chain_hash(last_block):
                return False

            # Check that the proof of Work is correct
            if not self.valid_chain_proof(last_block, block['proof']):
                return False

            last_block = block
            current_index += 1
        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://%s/chain' % node)

            if response.status_code == 200:
                response_data = response.json()  # 使用 .json() 直接解析 JSON
                length = response_data['length']
                chain = response_data['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer that ours
        if new_chain:
            self.chain = new_chain
            self.update_database_with_new_chain(new_chain)
            return True

        return False


    def update_database_with_new_chain(self, new_chain):
        # 遍历新链中的区块，将每个区块及其交易插入数据库
        Block.objects.all().delete()
        Transaction.objects.all().delete()
        for block_data in new_chain:
            index = block_data['index']
            timestamp = block_data['timestamp']
            proof = block_data['proof']
            previous_hash = block_data['previous_hash']

            # 创建并保存区块到数据库
            block = Block.objects.create(
                index=index,
                timestamp=timestamp,
                proof=proof,
                previous_hash=previous_hash
            )

            # 更新区块的交易信息
            transactions_data = block_data.get('transactions', [])
            for transaction_data in transactions_data:
                sender = transaction_data['sender']
                recipient = transaction_data['recipient']
                amount = transaction_data['amount']
                signature = base64.b64decode(transaction_data['signature'])

                # 创建并保存交易到数据库
                transaction = Transaction.objects.create(
                    sender=sender,
                    recipient=recipient,
                    amount=amount,
                    signature=signature
                )

                # 将交易关联到区块
                block.transactions.add(transaction)

    def valid_block(self, block, received_public_key):
        """
        验证一个区块的有效性
        :param block: 待验证的区块
        :return: True 如果区块有效，否则 False
        """
        # 1. 验证区块的索引
        blockchain = get_blockchain()
        if block['index'] == len(self.chain) and block['index'] != 1:
            print("接受区块在原区块已经存在")
            return False
        if block['index'] != len(self.chain) + 1 and block['index'] != 1:
            print('区块index对应不上')
            return False
        last_block = blockchain.last_block
        # 2. 验证区块的前一个哈希值
        if block['previous_hash'] != self.hash(last_block) and block['index'] != 1:
            print('哈希验证失败')
            return False

        # 3. 验证工作证明
        if not self.valid_proof(self.last_block, block['proof']) and block['index'] != 1:
            print("工作良验证失败")
            return False

        # 4. 验证交易
        if not self.valid_transactions(block['transactions'], received_public_key):
            print("交易验证失败")
            return False

        # 所有验证通过，区块有效
        return True


    def valid_transactions(self, transactions_list, received_public_key):
        """
        验证区块中的交易
        :param transactions: 区块中的交易列表
        :return: True 如果交易有效，否则 False
        """
        required_fields = ['sender', 'recipient', 'amount', 'signature']
        for transactions in transactions_list:
            if not all(field in transactions for field in required_fields):
                print("1")
                return False

            # 验证交易的签名
            if not self.verify_transaction(transactions,received_public_key):
                print("2")
                return False

        # 所有交易验证通过
        return True

    def valid_transaction(self, transaction):
        """
        验证单个交易的有效性
        :param transaction: 待验证的交易
        :return: True 如果交易有效，否则 False
        """
        # 检查交易字段是否完整
        required_fields = ['sender', 'recipient', 'amount']
        if not all(field in transaction for field in required_fields):
            return False

        # 验证交易的签名（这里可能涉及到更复杂的加密和签名机制）
        # 这里简化为检查是否有发送者信息
        if not transaction['sender']:
            return False

        # 进行其他的业务规则验证，例如账户余额是否足够等
        # 这里需要根据具体业务逻辑添加验证规则

        return True


node_identifier = str(uuid4()).replace('-','')

# Instantiate the Blockchain
#blockchain = Blockchain()
def get_blockchain():
    # 每次调用时才初始化（或使用单例缓存）
    return Blockchain()

def broadcast_block(block):
    # 获取其他节点列表
    blockchain = get_blockchain()
    nodes = blockchain.nodes
    # 遍历节点并发送新区块
    _, public_key = blockchain.node_key_pair
    block_dict = model_to_dict(block)

    # 将 _RSAPublicKey 对象转换为字符串
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    # 从 ManyRelatedManager 获取实际的模型实例列表
    transactions_list = list(block.transactions.all())
    # 将模型实例转换为字典
    transactions_data = [
        {

            'sender': transaction.sender,
            'recipient': transaction.recipient,
            'amount': transaction.amount,
            'signature': base64.b64encode(transaction.signature).decode('utf-8') # 将BinaryField转换为字符串
        }
        for transaction in transactions_list
    ]
    # 更新区块字典中的交易信息
    block_dict['transactions'] = transactions_data
    for node in nodes:
        url = f'http://{node}/receive_block/'
        requests.post(url, json={'block': block_dict, 'public_key': public_key_str})


@csrf_exempt
def receive_block(request):
    blockchain = get_blockchain()
    data = json.loads(request.body.decode('utf-8'))
    received_block = data.get('block')
    received_public_key = data.get('public_key')
    # 验证并添加新区块到本地区块链

    if blockchain.valid_block(received_block,received_public_key):
        if received_block['index'] == 1:
            blockchain.chain = []
            Block.objects.all().delete()
        blockchain.chain.append(received_block)
        # 保存区块到数据库
        index = received_block['index']
        timestamp = received_block['timestamp']
        proof = received_block['proof']
        previous_hash = received_block['previous_hash']

        # 根据你的模型字段进行适当的调整
        block = Block.objects.create(
            index=index,
            timestamp=timestamp,
            proof=proof,
            previous_hash=previous_hash
        )

        # 更新区块的交易信息
        transactions_data = received_block.get('transactions', [])
        for transaction_data in transactions_data:
            sender = transaction_data['sender']
            recipient = transaction_data['recipient']
            amount = transaction_data['amount']
            signature = base64.b64decode(transaction_data['signature'])

            # 创建并保存交易到数据库
            transaction = Transaction.objects.create(
                sender=sender,
                recipient=recipient,
                amount=amount,
                signature=signature
            )
            # 将交易关联到区块
            block.transactions.add(transaction)
        response_data = {'message': "Block received and added to the chain."}
    else:

        response_data = {'message': "Invalid block received."}
        print(response_data)
    return HttpResponse(json.dumps(response_data))


'''
产生新的区块
'''
def mine():
    blockchain = get_blockchain()
    last_block = blockchain.last_block
    #last_proof = last_block.proof
    proof = blockchain.proof_of_work(last_block)
    print(proof)

    # Forge the new Block by adding it to the chain
    block = blockchain.new_block(proof)

    response = {
        'message': "New Block Forged",
        'index': block.index,
        #'transactions': block.transactions,
        'proof': block.proof,
        'previous_hash': block.previous_hash,
    }
    print(response)
    return HttpResponse(json.dumps(response))

@csrf_exempt
def new_transaction(request):
    blockchain = get_blockchain()
    values = json.loads(request.body.decode('utf-8'))
    required = ['sender','recipient','amount']
    if not all(k in values for k in required):
        response = {'message': 'Missing values'}
        return HttpResponse(json.dumps(response), status=400)
    blockchain.chain = list(Block.objects.all().order_by('index'))
    chain_length = len(blockchain.chain)-1
    if len(blockchain.chain[chain_length].transactions.all()) < 4:
        blockchain.new_transaction(values['sender'],values['recipient'],values['amount'],chain_length)
        response = {'message': 'Transaction will be added to Block %s'% (chain_length+1)}
        return HttpResponse(json.dumps(response))
    else:
        broadcast_block(blockchain.chain[chain_length])
        mine()
        new_length = chain_length+1
        blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], chain_length+1)
        response = {'message': 'Transaction will be added to Block %s' % (new_length+1)}
        return HttpResponse(json.dumps(response))


def block_to_dict(block):
    # 将 Block 对象转换为字典
    transactions_list = list(block.transactions.all())
    transactions_data = [
        {
            'sender': transaction.sender,
            'recipient': transaction.recipient,
            'amount': transaction.amount,
            'signature': base64.b64encode(transaction.signature).decode('utf-8')
        }
        for transaction in transactions_list
    ]

    return {
        'index': block.index,
        'timestamp': block.timestamp,
        'proof': block.proof,
        'previous_hash': block.previous_hash,
        'transactions': transactions_data,
        # 其他字段根据需要添加
    }


@csrf_exempt
def full_chain(request):
    blockchain = get_blockchain()
    # 获取区块链数据
    blockchain.chain = list(Block.objects.all().order_by('index'))
    blocks_data = [block_to_dict(block) for block in blockchain.chain]

    # 构建响应数据
    response_data = {
        'chain': blocks_data,
        'length': len(blocks_data),
    }

    # 返回 JSON 响应
    return HttpResponse(json.dumps(response_data))


@csrf_exempt
def register_nodes(request):
    blockchain = get_blockchain()
    values = json.loads(request.body.decode('utf-8'))
    nodes = values.get('node')
    print(nodes)
    if nodes is None:
        response_data = {'error': 'Please supply a valid list of nodes'}
        return HttpResponse(json.dumps(response_data), status=400, content_type='application/json')
    for node in nodes:
        blockchain.register_node(node)
    response_data = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return HttpResponse(json.dumps(response_data), content_type='application/json')


def consensus(request):
    blockchain = get_blockchain()
    replaced = blockchain.resolve_conflicts()
    response_data = {
        'message': 'Our chain was replaced' if replaced else 'Our chain is authoritative',
        'chain': blockchain.chain,
        'node_identifier': node_identifier,  # 添加当前节点的标识符
    }
    return HttpResponse(json.dumps(response_data), content_type='application/json')





















