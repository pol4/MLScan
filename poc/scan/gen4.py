import pickle
import sys

class TestSubprocessEvasion:
    def __reduce__(self):
        # Ссылаемся на словарь уже загруженных модулей
        # Это проверяет, умеет ли сканер строить граф зависимостей объектов
        modules_dict = sys.modules
        
        # Извлекаем os опосредованно
        os_mod = modules_dict['os']
        
        # Безопасная команда для теста детекта
        return (os_mod.system, ('echo "Test Alert"',))

# Сериализация
bd = pickle.dumps(TestSubprocessEvasion())

with open("./evil4.pkl", "wb") as f:
    f.write(bd)
