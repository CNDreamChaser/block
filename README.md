### Django 区块链网络

这是一个基于 **Django 6.0** 实现的教学型区块链系统，完整支持**数字签名交易、工作量证明（PoW）、P2P 节点通信与自动共识同步**。所有数据通过 Django ORM 持久化存储，适合学习区块链核心原理或作为实验原型。

>  交易使用 **RSA-PSS** 签名，防篡改  
>  工作量证明要求哈希前缀为 `00000`（5 个零）  
>  节点通过 HTTP 自动广播区块并同步最长有效链  

---

###  核心特性

-  **交易签名验证**：每笔交易由发送方私钥签名，接收方可通过公钥验证。
-  **自动挖矿**：当区块包含 4 笔交易后，自动触发 PoW 挖矿并广播新区块。
-  **动态节点注册**：支持运行时添加对等节点（如 `localhost:8001`）。
-  **链冲突解决**：定期或手动触发共识机制，采用最长有效链。
-  **数据库持久化**：区块、交易、节点、密钥均保存在数据库中。
-  **无前端依赖**：纯 RESTful API 设计，可通过 `curl` 或 Postman 测试。

---

### 安装依赖
```bash
pip install -r requirements.txt
```
---

### 快速开始
#### 1. 初始化数据库
确保你的 Django 应用已包含上述模型，并执行：

```bash
python manage.py makemigrations
python manage.py migrate
```

 #### 2. 初始化本节点

 在 Postman 中创建新请求：

- **Method**: `POST`  
- **URL**: `http://localhost:8000/initialize_node/`  

- **Headers**:

  | Key             | Value               |
  |-----------------|---------------------|
  | `Content-Type`  | `application/json`  |

- **Body** → 选择 `raw` → 格式选 `JSON`，输入以下内容：

  ```json
  {
    "port": "localhost:8000"
  }
    ```
  成功响应示例：
  ```
  {
  "message": "Node initialized with address localhost:8000"
  }
    ```
 #### 3. 提交交易（自动触发挖矿）
  在 Postman 中创建新请求：

- **Method**: `POST`  
- **URL**: `http://localhost:8000/transactions/new/`  

- **Headers**:

  | Key             | Value               |
  |-----------------|---------------------|
  | `Content-Type`  | `application/json`  |

- **Body** → 选择 `raw` → 格式选 `JSON`，输入以下内容：

  ```json
  
    {
      "sender": "Alice",
      "recipient": "Bob",
      "amount": 10
    }
  
    ```
    成功响应示例：
  ```
  {
    "message": "Transaction added successfully"
  }
    ```
  重复此操作 4 次，系统将在第 4 笔交易后自动挖矿并广播新区块。

  
   #### 4. 查看完整区块链
  在 Postman 中创建新请求：

- **Method**: `GET`  
- **URL**: `http://localhost:8000/chain`  

- **Headers**:默认。

- **Body**：无需填写。  
  成功响应示例：
  ```
  {
  "chain": [
    {
      "index": 1,
      "timestamp": "2026-01-05 10:30:00",
      "proof": 12345,
      "previous_hash": "0",
      "transactions": []
    }
      ],
  "length": 1
   }

    ```
  ---

### API 接口说明

| 接口路径             | 方法   | 说明                                                                 |
|----------------------|--------|----------------------------------------------------------------------|
| `/initialize_node/`  | POST   | 初始化当前节点，需传 `{"port": "localhost:8000"}`                    |
| `/transactions/new/` | POST   | 创建新交易，需提供 `sender`, `recipient`, `amount`                   |
| `/chain`             | GET    | 获取完整区块链（注意：路径是 `/chain`）          |
| `/register`          | POST   | 注册多个对等节点，格式：`{"node": ["localhost:8001", "localhost:8002"]}` |
| `/resolve`           | GET    | 手动触发共识，同步最长有效链                                         |
| `/receive_block/`    | POST   | 接收其他节点广播的区块（自动验证）                                   |
| `/mine`              | GET    | （可选）手动挖矿（如果前端调用）                                     |


## 许可证

本项目采用 [MIT 许可证](LICENSE)，可自由用于个人、商业、学习、研究等任何用途。
