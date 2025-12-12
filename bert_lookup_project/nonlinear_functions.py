"""
非线性函数库 - 定义BERT中使用的激活函数
"""
import math

class NonlinearFunctions:
    @staticmethod
    def gelu(x: float) -> float:
        """GELU激活函数"""
        if x >= 0:
            return 0.5 * x * (1.0 + math.erf(x / math.sqrt(2.0)))
        else:
            # 对于负数，使用另一种形式避免精度问题
            return x * (1.0 + math.erf(x / math.sqrt(2.0))) * 0.5
    
    @staticmethod
    def gelu_approx(x: float) -> float:
        """GELU的近似实现（使用tanh）"""
        return 0.5 * x * (1.0 + math.tanh(
            math.sqrt(2.0 / math.pi) * (x + 0.044715 * x**3)
        ))
    
    @staticmethod
    def gelu_derivative(x: float) -> float:
        """GELU的导数"""
        phi = 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))
        pdf = math.exp(-x**2 / 2.0) / math.sqrt(2.0 * math.pi)
        return phi + x * pdf
    
    @staticmethod
    def tanh(x: float) -> float:
        """tanh函数"""
        return math.tanh(x)
    
    @staticmethod
    def tanh_derivative(x: float) -> float:
        """tanh的导数"""
        t = math.tanh(x)
        return 1.0 - t * t
    
    @staticmethod
    def sigmoid(x: float) -> float:
        """sigmoid函数"""
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        else:
            exp_x = math.exp(x)
            return exp_x / (1.0 + exp_x)
    
    @staticmethod
    def sigmoid_derivative(x: float) -> float:
        """sigmoid的导数"""
        s = NonlinearFunctions.sigmoid(x)
        return s * (1.0 - s)
    
    @staticmethod
    def relu(x: float) -> float:
        """ReLU函数"""
        return max(0.0, x)
    
    @staticmethod
    def relu_derivative(x: float) -> float:
        """ReLU的导数"""
        return 1.0 if x > 0 else 0.0
    
    @staticmethod
    def get_function(func_name: str):
        """根据名称获取函数"""
        funcs = {
            "gelu": NonlinearFunctions.gelu,
            "tanh": NonlinearFunctions.tanh,
            "sigmoid": NonlinearFunctions.sigmoid,
            "relu": NonlinearFunctions.relu
        }
        return funcs.get(func_name.lower(), NonlinearFunctions.gelu)
    
    @staticmethod
    def get_derivative(func_name: str):
        """根据名称获取导数函数"""
        derivs = {
            "gelu": NonlinearFunctions.gelu_derivative,
            "tanh": NonlinearFunctions.tanh_derivative,
            "sigmoid": NonlinearFunctions.sigmoid_derivative,
            "relu": NonlinearFunctions.relu_derivative
        }
        return derivs.get(func_name.lower(), NonlinearFunctions.gelu_derivative)