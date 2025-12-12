"""
查找表系统核心类 - 定点数转换和查找表计算
"""
import numpy as np
from config import Q16_SCALE, MAX_24BIT

class LookupTableSystem:
    def __init__(self):
        """初始化查找表系统"""
        # 两个12位查找表
        self.table0 = np.zeros(4096, dtype=np.int32)  # 基础值表
        self.table1 = np.zeros(4096, dtype=np.int32)  # 斜率表
        self.func_name = "gelu"  # 当前处理的函数名
    
    def float_to_q8_16(self, x: float) -> int:
        """
        将浮点数转换为Q8.16定点数
        
        参数:
            x: 浮点数，范围建议在[-128, 127.99998]
        
        返回:
            24位Q8.16定点数
        """
        # 限制范围，防止溢出
        if x > 127.99998:
            x = 127.99998
        elif x < -128.0:
            x = -128.0
        
        # 转换为Q8.16
        result = int(x * Q16_SCALE)
        
        # 处理负数（24位补码）
        if result < 0:
            result = (1 << 24) + result
        
        return result & MAX_24BIT
    
    def q8_16_to_float(self, x: int) -> float:
        """
        将Q8.16定点数转换为浮点数
        
        参数:
            x: 24位Q8.16定点数
        
        返回:
            浮点数
        """
        # 处理符号位（24位有符号数）
        if x & (1 << 23):  # 检查符号位（第24位）
            # 负数：转换为有符号整数
            x = x - (1 << 24)
        
        return x / Q16_SCALE
    
    def split_input(self, x_int: int):
        """
        将24位输入拆分为H(高12位)和L(低12位)
        
        参数:
            x_int: 24位Q8.16定点数
        
        返回:
            (H, L) 元组
        """
        H = (x_int >> 12) & 0xFFF  # 高12位
        L = x_int & 0xFFF          # 低12位
        return H, L
    
    def compute_approximation(self, x_int: int) -> int:
        """
        使用两个查找表计算函数近似值
        
        参数:
            x_int: 24位Q8.16定点数输入
        
        返回:
            24位Q8.16定点数输出
        """
        # 1. 拆分输入
        H, L = self.split_input(x_int)
        
        # 2. 查表
        A = self.table0[H]  # 基础值
        B = self.table1[H]  # 斜率
        
        # 3. 计算基础值（左移12位恢复精度）
        base = A << 12
        
        # 4. 计算增量: f'(x0) * L 的近似
        inc = (B * L) >> 4  # 注意：>>4 是预先设计的缩放
        
        # 5. 组合结果
        result = base + inc
        
        # 6. 限制到有效范围
        return result & MAX_24BIT
    
    def compute_float(self, x_float: float) -> float:
        """
        完整的浮点数到浮点数计算（方便使用）
        
        参数:
            x_float: 浮点数输入
        
        返回:
            浮点数输出
        """
        x_int = self.float_to_q8_16(x_float)
        result_int = self.compute_approximation(x_int)
        return self.q8_16_to_float(result_int)