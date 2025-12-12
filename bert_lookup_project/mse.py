"""
BERT非线性函数的灵活查找表近似系统
支持可变输入/输出位宽的查找表（≤12位）
作者：AI助手
日期：2024年
"""

import numpy as np
import math
import time
from typing import Tuple, List, Dict, Callable, Optional
import matplotlib.pyplot as plt

# ==================== 1. 非线性函数定义 ====================

class NonlinearFunctions:
    """BERT中使用的各种非线性函数"""
    
    @staticmethod
    def gelu(x: float) -> float:
        """GELU激活函数 - 精确实现"""
        if x >= 0:
            return 0.5 * x * (1.0 + math.erf(x / math.sqrt(2.0)))
        else:
            return 0.5 * x * (1.0 + math.erf(x / math.sqrt(2.0)))
    
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
        return 1.0 - math.tanh(x)**2
    
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
    def exp(x: float) -> float:
        """指数函数"""
        return math.exp(x)
    
    @staticmethod
    def exp_derivative(x: float) -> float:
        """指数函数的导数"""
        return math.exp(x)
    
    @staticmethod
    def relu(x: float) -> float:
        """ReLU函数"""
        return max(0.0, x)
    
    @staticmethod
    def relu_derivative(x: float) -> float:
        """ReLU的导数"""
        return 1.0 if x > 0 else 0.0

# ==================== 2. 灵活查找表系统 ====================

class FlexibleLookupSystem:
    """灵活的查找表系统，支持可变输入/输出位宽"""
    
    class TableConfig:
        """查找表配置类"""
        def __init__(self, input_bits: int, output_bits: int, 
                    scale_factor: float = 1.0, offset: float = 0.0):
            self.input_bits = input_bits
            self.output_bits = output_bits
            self.size = 1 << input_bits  # 表大小 = 2^input_bits
            self.max_output = (1 << output_bits) - 1
            self.scale_factor = scale_factor  # 输出缩放因子
            self.offset = offset  # 输出偏移量
    
    def __init__(self):
        self.tables = []  # 存储所有查找表数据
        self.table_configs = []  # 存储所有表配置
        self.function_name = "gelu"  # 当前处理的函数名
        
    def add_table(self, input_bits: int, output_bits: int, 
                 scale_factor: float = 1.0, offset: float = 0.0) -> int:
        """
        添加一个新的查找表
        
        参数:
            input_bits: 输入位宽 (≤12)
            output_bits: 输出位宽 (≤12)
            scale_factor: 输出缩放因子
            offset: 输出偏移量
            
        返回:
            表的索引
        """
        if input_bits > 12 or output_bits > 12:
            print(f"警告: 输入位宽({input_bits})或输出位宽({output_bits})超过12位，已限制为12位")
            input_bits = min(input_bits, 12)
            output_bits = min(output_bits, 12)
        
        config = self.TableConfig(input_bits, output_bits, scale_factor, offset)
        self.table_configs.append(config)
        
        # 初始化表内容为0
        table = np.zeros(config.size, dtype=np.int32)
        self.tables.append(table)
        
        table_idx = len(self.tables) - 1
        print(f"添加表{table_idx}: {input_bits}位输入 → {output_bits}位输出, 大小={config.size}")
        
        return table_idx
    
    def set_function(self, function_name: str):
        """设置要处理的函数"""
        self.function_name = function_name
    
    def generate_tables_for_function(self, function_name: str = None):
        """
        为指定函数生成查找表
        
        参数:
            function_name: 函数名 ("gelu", "tanh", "sigmoid", "exp")
        """
        if function_name:
            self.function_name = function_name
        
        # 清空现有表
        self.tables = []
        self.table_configs = []
        
        print(f"\n正在为 {self.function_name} 函数生成查找表...")
        
        # 根据函数选择不同的表配置
        if self.function_name == "gelu":
            return self._generate_gelu_tables()
        elif self.function_name == "tanh":
            return self._generate_tanh_tables()
        elif self.function_name == "sigmoid":
            return self._generate_sigmoid_tables()
        elif self.function_name == "exp":
            return self._generate_exp_tables()
        else:
            print(f"错误: 不支持的函数 '{self.function_name}'")
            return None
    
    def _generate_gelu_tables(self) -> Dict[str, int]:
        """为GELU函数生成查找表"""
        
        # 配置: 4个表，不同精度
        table1_idx = self.add_table(input_bits=10, output_bits=12, scale_factor=4.0, offset=2.0)
        table2_idx = self.add_table(input_bits=9, output_bits=10, scale_factor=1.2, offset=0.0)
        table3_idx = self.add_table(input_bits=8, output_bits=8, scale_factor=0.1, offset=0.0)
        table4_idx = self.add_table(input_bits=8, output_bits=8, scale_factor=0.05, offset=0.0)
        
        print("生成表1 (GELU基础值)...")
        for i in range(self.table_configs[0].size):  # 0-1023
            # 将索引映射到x值: [-4, 4]
            x = (i - 512) * (8.0 / 1024)
            
            # 计算GELU值
            gelu_val = NonlinearFunctions.gelu(x)
            
            # 缩放和量化
            scaled = (gelu_val + 2.0) * 512  # 映射到[0, 4096)
            quantized = int(scaled)
            quantized = max(0, min(quantized, 4095))  # 限制到12位
            
            self.tables[0][i] = quantized
        
        print("生成表2 (GELU导数)...")
        for i in range(self.table_configs[1].size):  # 0-511
            x = (i - 256) * (8.0 / 512)
            
            # 计算GELU导数
            derivative = NonlinearFunctions.gelu_derivative(x)
            
            # 缩放和量化 (导数范围约[0, 1.2])
            scaled = derivative * (1023 / 1.2)  # 映射到[0, 1023]
            quantized = int(scaled)
            quantized = max(0, min(quantized, 1023))
            
            self.tables[1][i] = quantized
        
        print("生成表3 (中间位修正)...")
        for i in range(self.table_configs[2].size):  # 0-255
            # 中间8位的修正项 (模拟二阶导数效果)
            t = i / 255.0
            correction = 0.1 * t * (1 - t)  # 抛物线
            scaled = correction * 255
            quantized = int(scaled)
            quantized = max(0, min(quantized, 255))
            
            self.tables[2][i] = quantized
        
        print("生成表4 (低位修正)...")
        for i in range(self.table_configs[3].size):  # 0-255
            # 低8位的修正项 (模拟三阶导数效果)
            t = i / 255.0
            correction = 0.05 * t * (1 - t) * (2 * t - 1)  # 三次曲线
            scaled = correction * 255
            quantized = int(scaled)
            quantized = max(0, min(quantized, 255))
            
            self.tables[3][i] = quantized
        
        print("GELU查找表生成完成!")
        
        return {
            'table1': table1_idx,
            'table2': table2_idx,
            'table3': table3_idx,
            'table4': table4_idx
        }
    
    def _generate_tanh_tables(self) -> Dict[str, int]:
        """为tanh函数生成查找表"""
        
        # tanh是对称的，可以用更少的表
        table1_idx = self.add_table(input_bits=10, output_bits=12, scale_factor=1.0, offset=0.5)
        table2_idx = self.add_table(input_bits=9, output_bits=10, scale_factor=1.0, offset=0.0)
        
        print("生成表1 (tanh基础值)...")
        for i in range(self.table_configs[0].size):  # 0-1023
            # x范围: [-4, 4]
            x = (i - 512) * (8.0 / 1024)
            
            # 计算tanh值
            tanh_val = NonlinearFunctions.tanh(x)
            
            # 缩放: tanh范围是[-1, 1]，映射到[0, 4095]
            scaled = (tanh_val + 1.0) * 2047.5
            quantized = int(scaled)
            quantized = max(0, min(quantized, 4095))
            
            self.tables[0][i] = quantized
        
        print("生成表2 (tanh导数)...")
        for i in range(self.table_configs[1].size):  # 0-511
            x = (i - 256) * (8.0 / 512)
            
            # 计算tanh导数
            derivative = NonlinearFunctions.tanh_derivative(x)
            
            # 缩放: 导数范围是[0, 1]
            scaled = derivative * 1023
            quantized = int(scaled)
            quantized = max(0, min(quantized, 1023))
            
            self.tables[1][i] = quantized
        
        print("tanh查找表生成完成!")
        
        return {'table1': table1_idx, 'table2': table2_idx}
    
    def _generate_sigmoid_tables(self) -> Dict[str, int]:
        """为sigmoid函数生成查找表"""
        
        # sigmoid是非对称的，但形状简单
        table1_idx = self.add_table(input_bits=10, output_bits=12, scale_factor=1.0, offset=0.0)
        table2_idx = self.add_table(input_bits=9, output_bits=10, scale_factor=0.25, offset=0.0)
        
        print("生成表1 (sigmoid基础值)...")
        for i in range(self.table_configs[0].size):  # 0-1023
            # x范围: [-8, 8] (sigmoid需要更宽的范围)
            x = (i - 512) * (16.0 / 1024)
            
            # 计算sigmoid值
            sigmoid_val = NonlinearFunctions.sigmoid(x)
            
            # 缩放: sigmoid范围是[0, 1]，映射到[0, 4095]
            scaled = sigmoid_val * 4095
            quantized = int(scaled)
            quantized = max(0, min(quantized, 4095))
            
            self.tables[0][i] = quantized
        
        print("生成表2 (sigmoid导数)...")
        for i in range(self.table_configs[1].size):  # 0-511
            x = (i - 256) * (16.0 / 512)
            
            # 计算sigmoid导数
            derivative = NonlinearFunctions.sigmoid_derivative(x)
            
            # 缩放: 导数范围是[0, 0.25]
            scaled = derivative * 4092  # 1023 / 0.25 ≈ 4092
            quantized = int(scaled)
            quantized = max(0, min(quantized, 1023))
            
            self.tables[1][i] = quantized
        
        print("sigmoid查找表生成完成!")
        
        return {'table1': table1_idx, 'table2': table2_idx}
    
    def _generate_exp_tables(self) -> Dict[str, int]:
        """为exp函数生成查找表（用于softmax）"""
        
        # exp函数增长很快，需要特殊处理
        table1_idx = self.add_table(input_bits=10, output_bits=12, scale_factor=1.0, offset=0.0)
        table2_idx = self.add_table(input_bits=10, output_bits=10, scale_factor=1.0, offset=0.0)
        
        print("生成表1 (exp整数部分)...")
        for i in range(self.table_configs[0].size):  # 0-1023
            # x范围: [-8, 8] 但只处理负数和小的正数
            # 实际中，softmax会减去最大值，所以输入通常是负数或小的正数
            x = (i - 768) * (8.0 / 1024)  # 偏置到负数区域
            
            # 计算exp值，但要处理溢出
            exp_val = NonlinearFunctions.exp(x)
            
            # 限制范围，避免溢出
            max_exp = 100.0  # 合理上限
            exp_val = min(exp_val, max_exp)
            
            # 缩放: 映射到[0, 4095]
            scaled = exp_val * (4095 / max_exp)
            quantized = int(scaled)
            quantized = max(0, min(quantized, 4095))
            
            self.tables[0][i] = quantized
        
        print("生成表2 (exp小数部分)...")
        for i in range(self.table_configs[1].size):  # 0-1023
            # 处理小数部分: [0, 1)
            x = i / 1024.0
            
            # 计算exp的小数部分
            exp_val = NonlinearFunctions.exp(x)
            
            # 缩放: exp(1) ≈ 2.718，所以范围是[1, 2.718]
            scaled = (exp_val - 1.0) * (1023 / 1.718)
            quantized = int(scaled)
            quantized = max(0, min(quantized, 1023))
            
            self.tables[1][i] = quantized
        
        print("exp查找表生成完成!")
        
        return {'table1': table1_idx, 'table2': table2_idx}
    
    def compute_approximation(self, x: float) -> float:
        """
        使用查找表计算函数近似值
        
        参数:
            x: 输入值
            
        返回:
            近似值
        """
        if not self.tables:
            print("错误: 查找表未生成！")
            return 0.0
        
        # 根据函数类型选择计算方法
        if self.function_name == "gelu":
            return self._compute_gelu_approx(x)
        elif self.function_name == "tanh":
            return self._compute_tanh_approx(x)
        elif self.function_name == "sigmoid":
            return self._compute_sigmoid_approx(x)
        elif self.function_name == "exp":
            return self._compute_exp_approx(x)
        else:
            print(f"错误: 不支持的函数 '{self.function_name}'")
            return 0.0
    
    def _compute_gelu_approx(self, x: float) -> float:
        """计算GELU的近似值"""
        # 限制输入范围
        x_clamped = max(min(x, 4.0), -4.0)
        
        # 表1: 基础值
        # 归一化到[0, 1]
        normalized = (x_clamped + 4.0) / 8.0
        idx1 = int(normalized * 1024)  # 10位索引
        idx1 = max(0, min(idx1, 1023))
        
        # 获取表1的值并反量化
        val1_quantized = self.tables[0][idx1]
        # 反缩放: 从[0, 4095]映射回GELU值
        val1 = (val1_quantized / 512.0) - 2.0
        
        # 表2: 导数
        idx2 = int(normalized * 512)  # 9位索引
        idx2 = max(0, min(idx2, 511))
        
        val2_quantized = self.tables[1][idx2]
        # 反缩放: 从[0, 1023]映射回导数值
        derivative = val2_quantized * (1.2 / 1023.0)
        
        # 表3和表4: 修正项
        # 计算在表1区间内的小数部分
        t = normalized * 1024 - idx1
        
        # 使用t的高8位作为表3索引
        idx3 = int(t * 256)  # 8位索引
        idx3 = max(0, min(idx3, 255))
        
        val3_quantized = self.tables[2][idx3]
        correction1 = val3_quantized * (0.1 / 255.0)
        
        # 使用t的低8位作为表4索引
        t2 = t * 256 - idx3
        idx4 = int(t2 * 256)  # 8位索引
        idx4 = max(0, min(idx4, 255))
        
        val4_quantized = self.tables[3][idx4]
        correction2 = val4_quantized * (0.05 / 255.0)
        
        # 线性插值 + 修正
        # 区间宽度: 8.0 / 1024 ≈ 0.0078125
        interval_width = 8.0 / 1024
        result = val1 + derivative * t * interval_width + correction1 + correction2
        
        return result
    
    def _compute_tanh_approx(self, x: float) -> float:
        """计算tanh的近似值"""
        # 限制输入范围
        x_clamped = max(min(x, 4.0), -4.0)
        
        # 表1: 基础值
        normalized = (x_clamped + 4.0) / 8.0
        idx1 = int(normalized * 1024)  # 10位索引
        idx1 = max(0, min(idx1, 1023))
        
        # 获取表1的值并反量化
        val1_quantized = self.tables[0][idx1]
        # 反缩放: 从[0, 4095]映射回tanh值
        val1 = (val1_quantized / 2047.5) - 1.0
        
        # 表2: 导数（用于插值）
        idx2 = int(normalized * 512)  # 9位索引
        idx2 = max(0, min(idx2, 511))
        
        val2_quantized = self.tables[1][idx2]
        derivative = val2_quantized / 1023.0
        
        # 线性插值
        t = normalized * 1024 - idx1
        interval_width = 8.0 / 1024
        result = val1 + derivative * t * interval_width
        
        return result
    
    def _compute_sigmoid_approx(self, x: float) -> float:
        """计算sigmoid的近似值"""
        # 限制输入范围
        x_clamped = max(min(x, 8.0), -8.0)
        
        # 表1: 基础值
        normalized = (x_clamped + 8.0) / 16.0
        idx1 = int(normalized * 1024)  # 10位索引
        idx1 = max(0, min(idx1, 1023))
        
        # 获取表1的值并反量化
        val1_quantized = self.tables[0][idx1]
        # 反缩放: 从[0, 4095]映射回sigmoid值
        val1 = val1_quantized / 4095.0
        
        # 表2: 导数
        idx2 = int(normalized * 512)  # 9位索引
        idx2 = max(0, min(idx2, 511))
        
        val2_quantized = self.tables[1][idx2]
        derivative = val2_quantized / 4092.0
        
        # 线性插值
        t = normalized * 1024 - idx1
        interval_width = 16.0 / 1024
        result = val1 + derivative * t * interval_width
        
        # sigmoid范围是[0, 1]
        return max(0.0, min(result, 1.0))
    
    def _compute_exp_approx(self, x: float) -> float:
        """计算exp的近似值"""
        # 限制输入范围（主要用于softmax，x通常是负数）
        x_clamped = max(min(x, 2.0), -8.0)
        
        if x_clamped < 0:
            # 使用表1（处理负数）
            normalized = (x_clamped + 8.0) / 10.0  # 映射[-8, 2]到[0, 1]
            idx1 = int(normalized * 1024)  # 10位索引
            idx1 = max(0, min(idx1, 1023))
            
            val1_quantized = self.tables[0][idx1]
            # 反缩放: 从[0, 4095]映射回exp值
            result = val1_quantized * (100.0 / 4095.0)
        else:
            # 对于正数，使用表2（处理小数部分）
            # 分解为整数部分和小数部分
            integer_part = int(x_clamped)
            fractional_part = x_clamped - integer_part
            
            # 计算整数部分: exp(整数) = exp(1)^整数
            exp_integer = math.exp(1.0) ** integer_part
            
            # 计算小数部分: 使用表2
            idx2 = int(fractional_part * 1024)  # 10位索引
            idx2 = max(0, min(idx2, 1023))
            
            val2_quantized = self.tables[1][idx2]
            exp_fractional = 1.0 + val2_quantized * (1.718 / 1023.0)
            
            result = exp_integer * exp_fractional
        
        return result

# ==================== 3. 误差分析工具 ====================

class ErrorAnalyzer:
    """误差分析工具"""
    
    def __init__(self, lookup_system: FlexibleLookupSystem):
        self.lookup_system = lookup_system
        
    def compute_errors(self, num_samples: int = 10000, 
                      input_range: Tuple[float, float] = (-4, 4)) -> Dict:
        """
        计算查找表近似的误差统计
        
        参数:
            num_samples: 测试样本数
            input_range: 输入范围
            
        返回:
            误差统计字典
        """
        # 获取精确函数
        if self.lookup_system.function_name == "gelu":
            exact_func = NonlinearFunctions.gelu
        elif self.lookup_system.function_name == "tanh":
            exact_func = NonlinearFunctions.tanh
        elif self.lookup_system.function_name == "sigmoid":
            exact_func = NonlinearFunctions.sigmoid
        elif self.lookup_system.function_name == "exp":
            exact_func = NonlinearFunctions.exp
        else:
            print(f"错误: 不支持的函数 '{self.lookup_system.function_name}'")
            return {}
        
        # 调整sigmoid的输入范围
        if self.lookup_system.function_name == "sigmoid":
            input_range = (-8, 8)
        elif self.lookup_system.function_name == "exp":
            input_range = (-8, 2)
        
        # 收集误差
        abs_errors = []
        rel_errors = []
        max_abs_error = 0
        max_rel_error = 0
        
        for _ in range(num_samples):
            # 随机生成输入值
            x = np.random.uniform(input_range[0], input_range[1])
            
            # 精确值
            exact = exact_func(x)
            
            # 近似值
            approx = self.lookup_system.compute_approximation(x)
            
            # 计算误差
            abs_error = abs(exact - approx)
            abs_errors.append(abs_error)
            
            if abs(exact) > 1e-10:
                rel_error = abs_error / abs(exact)
                rel_errors.append(rel_error)
                max_rel_error = max(max_rel_error, rel_error)
            
            max_abs_error = max(max_abs_error, abs_error)
        
        # 计算统计量
        mae = np.mean(abs_errors)
        mse = np.mean([e**2 for e in abs_errors])
        rmse = np.sqrt(mse)
        
        # 百分位数
        abs_errors_sorted = np.sort(abs_errors)
        p95_abs = abs_errors_sorted[int(0.95 * len(abs_errors_sorted))]
        p99_abs = abs_errors_sorted[int(0.99 * len(abs_errors_sorted))]
        
        if rel_errors:
            rel_errors_sorted = np.sort(rel_errors)
            p95_rel = rel_errors_sorted[int(0.95 * len(rel_errors_sorted))]
            p99_rel = rel_errors_sorted[int(0.99 * len(rel_errors_sorted))]
        else:
            p95_rel = p99_rel = 0.0
        
        return {
            "function": self.lookup_system.function_name,
            "mae": mae,
            "mse": mse,
            "rmse": rmse,
            "max_abs_error": max_abs_error,
            "max_rel_error": max_rel_error,
            "p95_abs_error": p95_abs,
            "p99_abs_error": p99_abs,
            "p95_rel_error": p95_rel,
            "p99_rel_error": p99_rel,
            "num_samples": num_samples,
            "input_range": input_range,
            "abs_errors": abs_errors,
            "rel_errors": rel_errors
        }
    
    def print_error_summary(self, errors: Dict):
        """打印误差摘要"""
        print(f"\n{'='*60}")
        print(f"{errors['function'].upper()} 函数误差分析")
        print(f"{'='*60}")
        print(f"测试样本数: {errors['num_samples']}")
        print(f"输入范围: [{errors['input_range'][0]}, {errors['input_range'][1]}]")
        print(f"\n绝对误差统计:")
        print(f"  MAE  (平均绝对误差): {errors['mae']:.6f}")
        print(f"  MSE  (均方误差):     {errors['mse']:.8f}")
        print(f"  RMSE (均方根误差):   {errors['rmse']:.6f}")
        print(f"  最大绝对误差:        {errors['max_abs_error']:.6f}")
        print(f"  95%绝对误差:        {errors['p95_abs_error']:.6f}")
        print(f"  99%绝对误差:        {errors['p99_abs_error']:.6f}")
        
        if errors['rel_errors']:
            print(f"\n相对误差统计:")
            print(f"  最大相对误差:        {errors['max_rel_error']:.6f}")
            if errors['p95_rel_error'] > 0:
                print(f"  95%相对误差:        {errors['p95_rel_error']:.6f}")
                print(f"  99%相对误差:        {errors['p99_rel_error']:.6f}")
    
    def plot_error_distribution(self, errors: Dict, save_path: str = None):
        """绘制误差分布图"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        # 绝对误差直方图
        axes[0, 0].hist(errors["abs_errors"], bins=50, alpha=0.7, color='blue', edgecolor='black')
        axes[0, 0].set_xlabel('绝对误差')
        axes[0, 0].set_ylabel('频数')
        axes[0, 0].set_title(f'{errors["function"].upper()} - 绝对误差分布')
        axes[0, 0].grid(True, alpha=0.3)
        
        # 相对误差直方图（如果存在）
        if errors["rel_errors"]:
            axes[0, 1].hist(errors["rel_errors"], bins=50, alpha=0.7, color='red', edgecolor='black')
            axes[0, 1].set_xlabel('相对误差')
            axes[0, 1].set_ylabel('频数')
            axes[0, 1].set_title(f'{errors["function"].upper()} - 相对误差分布')
            axes[0, 1].grid(True, alpha=0.3)
        else:
            axes[0, 1].text(0.5, 0.5, '无相对误差数据', 
                           ha='center', va='center', transform=axes[0, 1].transAxes)
            axes[0, 1].set_title(f'{errors["function"].upper()} - 相对误差分布')
        
        # 误差与输入值的关系（采样）
        # 生成测试数据
        x_min, x_max = errors["input_range"]
        x_values = np.linspace(x_min, x_max, 200)
        abs_errors_vs_x = []
        
        # 获取精确函数
        if errors["function"] == "gelu":
            exact_func = NonlinearFunctions.gelu
        elif errors["function"] == "tanh":
            exact_func = NonlinearFunctions.tanh
        elif errors["function"] == "sigmoid":
            exact_func = NonlinearFunctions.sigmoid
        elif errors["function"] == "exp":
            exact_func = NonlinearFunctions.exp
        
        for x in x_values:
            exact = exact_func(x)
            approx = self.lookup_system.compute_approximation(x)
            abs_errors_vs_x.append(abs(exact - approx))
        
        axes[1, 0].plot(x_values, abs_errors_vs_x, 'g-', alpha=0.7, linewidth=2)
        axes[1, 0].set_xlabel('输入值 x')
        axes[1, 0].set_ylabel('绝对误差')
        axes[1, 0].set_title(f'{errors["function"].upper()} - 误差随输入变化')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 统计信息文本
        stats_text = (
            f"MAE: {errors['mae']:.6f}\n"
            f"MSE: {errors['mse']:.8f}\n"
            f"RMSE: {errors['rmse']:.6f}\n"
            f"Max Abs: {errors['max_abs_error']:.6f}\n"
            f"Max Rel: {errors['max_rel_error']:.6f}\n"
            f"95% Abs: {errors['p95_abs_error']:.6f}\n"
            f"99% Abs: {errors['p99_abs_error']:.6f}"
        )
        
        axes[1, 1].text(0.1, 0.5, stats_text, fontsize=10, 
                       verticalalignment='center',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        axes[1, 1].axis('off')
        
        plt.suptitle(f'{errors["function"].upper()}函数 - 灵活查找表近似误差分析', fontsize=14, fontweight='bold')
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"图表已保存到: {save_path}")
        
        plt.show()

# ==================== 4. 性能测试工具 ====================

class PerformanceTester:
    """性能测试工具"""
    
    @staticmethod
    def compare_speed(lookup_system: FlexibleLookupSystem, 
                     num_samples: int = 100000):
        """
        比较浮点计算和查表计算的速度
        
        参数:
            lookup_system: 查找表系统
            num_samples: 测试样本数
        """
        # 获取精确函数
        func_name = lookup_system.function_name
        if func_name == "gelu":
            exact_func = NonlinearFunctions.gelu
        elif func_name == "tanh":
            exact_func = NonlinearFunctions.tanh
        elif func_name == "sigmoid":
            exact_func = NonlinearFunctions.sigmoid
        elif func_name == "exp":
            exact_func = NonlinearFunctions.exp
        
        # 生成测试数据
        if func_name == "sigmoid":
            test_inputs = np.random.uniform(-8, 8, num_samples)
        elif func_name == "exp":
            test_inputs = np.random.uniform(-8, 2, num_samples)
        else:
            test_inputs = np.random.uniform(-4, 4, num_samples)
        
        print(f"\n性能测试: {func_name.upper()} 函数")
        print(f"测试样本数: {num_samples}")
        print("-" * 50)
        
        # 测试1: 浮点计算
        print("1. 浮点计算...")
        start_time = time.time()
        float_results = [exact_func(x) for x in test_inputs]
        float_time = time.time() - start_time
        
        # 测试2: 查表计算
        print("2. 查表计算...")
        start_time = time.time()
        table_results = [lookup_system.compute_approximation(x) for x in test_inputs]
        table_time = time.time() - start_time
        
        # 计算误差
        errors = [abs(f - t) for f, t in zip(float_results, table_results)]
        avg_error = np.mean(errors)
        max_error = max(errors)
        
        # 打印结果
        print("\n结果:")
        print(f"浮点计算时间: {float_time:.4f} 秒")
        print(f"查表计算时间: {table_time:.4f} 秒")
        print(f"加速比: {float_time/table_time:.2f}x")
        print(f"平均误差: {avg_error:.6f}")
        print(f"最大误差: {max_error:.6f}")
        
        return {
            "float_time": float_time,
            "table_time": table_time,
            "speedup": float_time / table_time,
            "avg_error": avg_error,
            "max_error": max_error
        }

# ==================== 5. 主测试程序 ====================

def main():
    """主测试程序"""
    print("=" * 60)
    print("BERT非线性函数的灵活查找表近似系统")
    print("支持可变输入/输出位宽 (≤12位)")
    print("=" * 60)
    
    # 测试的函数列表
    functions_to_test = ["gelu", "tanh", "sigmoid", "exp"]
    
    all_results = {}
    
    for func_name in functions_to_test:
        print(f"\n{'='*60}")
        print(f"测试函数: {func_name.upper()}")
        print(f"{'='*60}")
        
        # 1. 创建查找表系统
        lookup_system = FlexibleLookupSystem()
        lookup_system.set_function(func_name)
        
        # 2. 生成查找表
        table_indices = lookup_system.generate_tables_for_function(func_name)
        
        if not table_indices:
            print(f"生成 {func_name} 查找表失败，跳过...")
            continue
        
        # 3. 测试几个关键点
        print(f"\n{func_name.upper()} 关键点测试:")
        print("-" * 50)
        
        if func_name == "sigmoid":
            test_points = [-8.0, -4.0, -2.0, -1.0, 0.0, 1.0, 2.0, 4.0, 8.0]
        elif func_name == "exp":
            test_points = [-8.0, -4.0, -2.0, -1.0, 0.0, 0.5, 1.0, 1.5, 2.0]
        else:
            test_points = [-4.0, -2.0, -1.0, -0.5, 0.0, 0.5, 1.0, 2.0, 4.0]
        
        for x in test_points:
            # 精确值
            if func_name == "gelu":
                exact = NonlinearFunctions.gelu(x)
            elif func_name == "tanh":
                exact = NonlinearFunctions.tanh(x)
            elif func_name == "sigmoid":
                exact = NonlinearFunctions.sigmoid(x)
            elif func_name == "exp":
                exact = NonlinearFunctions.exp(x)
            
            # 近似值
            approx = lookup_system.compute_approximation(x)
            
            # 误差
            abs_error = abs(exact - approx)
            rel_error = abs_error / max(abs(exact), 1e-10) * 100
            
            print(f"x={x:6.2f}: 精确值={exact:10.6f}, 近似值={approx:10.6f}, "
                  f"绝对误差={abs_error:10.6f}, 相对误差={rel_error:6.2f}%")
        
        # 4. 全面误差分析
        print(f"\n{func_name.upper()} 全面误差分析:")
        print("-" * 50)
        
        analyzer = ErrorAnalyzer(lookup_system)
        errors = analyzer.compute_errors(num_samples=10000)
        analyzer.print_error_summary(errors)
        
        # 5. 性能测试
        print(f"\n{func_name.upper()} 性能测试:")
        print("-" * 50)
        
        perf_tester = PerformanceTester()
        perf_results = perf_tester.compare_speed(lookup_system, num_samples=10000)
        
        # 保存结果
        all_results[func_name] = {
            "errors": errors,
            "performance": perf_results
        }
        
        # 6. 绘制误差分布图
        try:
            analyzer.plot_error_distribution(errors, save_path=f"{func_name}_error_analysis.png")
        except Exception as e:
            print(f"绘制图表时出错: {e}")
            print("请确保已安装matplotlib: pip install matplotlib")
    
    # 7. 对比所有函数
    print(f"\n{'='*60}")
    print("所有函数性能对比")
    print(f"{'='*60}")
    
    print(f"\n{'函数':<10} {'MAE':<12} {'RMSE':<12} {'最大绝对误差':<15} {'加速比':<10}")
    print("-" * 60)
    
    for func_name in functions_to_test:
        if func_name in all_results:
            errors = all_results[func_name]["errors"]
            perf = all_results[func_name]["performance"]
            print(f"{func_name:<10} {errors['mae']:<12.6f} {errors['rmse']:<12.6f} "
                  f"{errors['max_abs_error']:<15.6f} {perf['speedup']:<10.2f}x")
    
    print(f"\n{'='*60}")
    print("测试完成!")
    print(f"{'='*60}")
    
    return all_results

def quick_test():
    """快速测试（只测试GELU函数）"""
    print("快速测试: GELU函数")
    print("-" * 40)
    
    # 创建查找表系统
    lookup_system = FlexibleLookupSystem()
    lookup_system.set_function("gelu")
    
    # 生成查找表
    print("生成查找表...")
    lookup_system.generate_tables_for_function("gelu")
    
    # 测试几个点
    test_points = [-3.0, -1.5, -0.5, 0.0, 0.5, 1.5, 3.0]
    
    for x in test_points:
        exact = NonlinearFunctions.gelu(x)
        approx = lookup_system.compute_approximation(x)
        error = abs(exact - approx)
        rel_error = error / max(abs(exact), 1e-10) * 100
        
        print(f"x={x:5.1f}: 精确值={exact:8.4f}, 近似值={approx:8.4f}, "
              f"误差={error:8.4f}, 相对误差={rel_error:6.2f}%")
    
    # 快速误差分析
    print("\n快速误差分析...")
    analyzer = ErrorAnalyzer(lookup_system)
    errors = analyzer.compute_errors(num_samples=1000)
    
    print(f"MAE (平均绝对误差): {errors['mae']:.6f}")
    print(f"RMSE (均方根误差): {errors['rmse']:.6f}")
    print(f"最大绝对误差: {errors['max_abs_error']:.6f}")

# ==================== 6. 程序入口 ====================

if __name__ == "__main__":
    print("BERT非线性函数的灵活查找表系统")
    print("1. 运行完整测试")
    print("2. 快速测试(GELU)")
    print("3. 退出")
    
    choice = input("\n请选择 (1/2/3): ").strip()
    
    if choice == "1":
        # 运行完整测试
        all_results = main()
    elif choice == "2":
        # 快速测试
        quick_test()
    elif choice == "3":
        print("退出程序")
    else:
        print("无效选择，运行完整测试...")
        all_results = main()