"""
查找表生成器 - 预计算查找表内容
"""
import numpy as np
from nonlinear_functions import NonlinearFunctions
from lookup_table_system import LookupTableSystem
from config import TABLE_SIZE

class TableGenerator:
    def __init__(self, function_name: str = "gelu"):
        """
        初始化查找表生成器
        
        参数:
            function_name: 函数名称，可选 "gelu", "tanh", "sigmoid", "relu"
        """
        self.function_name = function_name.lower()
        self.table_system = LookupTableSystem()
        self.table_system.func_name = self.function_name
        
    def generate_tables(self, scaling_factor: float = 1.0) -> LookupTableSystem:
        """
        生成两个查找表
        
        参数:
            scaling_factor: 缩放因子，用于调整数值范围
        
        返回:
            配置好的LookupTableSystem对象
        """
        # 获取函数和导数
        func = NonlinearFunctions.get_function(self.function_name)
        deriv = NonlinearFunctions.get_derivative(self.function_name)
        
        print(f"正在生成 {self.function_name} 函数的查找表...")
        
        for H in range(TABLE_SIZE):  # H从0到4095
            # 计算实际的浮点输入值
            # 注意：H是高12位，在Q8.16格式中对应 H/16.0
            x0 = H / 16.0
            
            # 计算函数值和导数的浮点值
            f_val = func(x0)
            df_val = deriv(x0)
            
            # 转换为定点数（Q8.16格式）
            f_fixed = self.table_system.float_to_q8_16(f_val * scaling_factor)
            df_fixed = self.table_system.float_to_q8_16(df_val * scaling_factor)
            
            # 存储到表0：基础函数值的高12位（四舍五入）
            # +2048实现四舍五入（因为2048 = 2^11 = 一半的量化步长）
            self.table_system.table0[H] = (f_fixed + 2048) >> 12
            
            # 存储到表1：导数的高12位
            self.table_system.table1[H] = df_fixed >> 12
            
            # 显示进度
            if H % 512 == 0:  # 每512个点显示一次进度
                progress = (H + 1) / TABLE_SIZE * 100
                print(f"进度: {progress:.1f}%", end='\r')
        
        print(f"查找表生成完成！共 {TABLE_SIZE} 个条目")
        return self.table_system
    
    def save_tables(self, filepath: str = "tables.npy"):
        """
        保存查找表到文件
        
        参数:
            filepath: 文件路径
        """
        np.save(filepath, {
            'table0': self.table_system.table0,
            'table1': self.table_system.table1,
            'func_name': self.function_name
        })
        print(f"查找表已保存到 {filepath}")
    
    def load_tables(self, filepath: str = "tables.npy") -> LookupTableSystem:
        """
        从文件加载查找表
        
        参数:
            filepath: 文件路径
        
        返回:
            LookupTableSystem对象
        """
        data = np.load(filepath, allow_pickle=True).item()
        self.table_system.table0 = data['table0']
        self.table_system.table1 = data['table1']
        self.function_name = data['func_name']
        self.table_system.func_name = self.function_name
        print(f"查找表已从 {filepath} 加载")
        return self.table_system