"""
专门用于计算查找表近似方案的MAE和MSE
"""
import numpy as np
import math
import time

# ===================== 1. 核心函数定义 =====================
class NonlinearFunctions:
    """非线性函数定义"""
    @staticmethod
    def gelu(x: float) -> float:
        return 0.5 * x * (1.0 + math.erf(x / math.sqrt(2.0)))
    
    @staticmethod
    def tanh(x: float) -> float:
        return math.tanh(x)
    
    @staticmethod
    def sigmoid(x: float) -> float:
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        else:
            exp_x = math.exp(x)
            return exp_x / (1.0 + exp_x)

# ===================== 2. 查找表系统 =====================
class LookupTableSystem:
    """查找表近似计算核心"""
    Q16_SCALE = 1 << 16  # 65536
    MAX_24BIT = (1 << 30) - 1
    
    def __init__(self):
        self.table0 = np.zeros(4096, dtype=np.int32)  # 基础值表
        self.table1 = np.zeros(4096, dtype=np.int32)  # 斜率表
    
    def float_to_q8_16(self, x: float) -> int:
        """浮点数转Q8.16定点数"""
        if x > 127.99998:
            x = 127.99998
        elif x < -128.0:
            x = -128.0
        
        result = int(x * self.Q16_SCALE)
        if result < 0:
            result = (1 << 30) + result
        return result & self.MAX_24BIT
    
    def q8_16_to_float(self, x: int) -> float:
        """Q8.16定点数转浮点数"""
        if x & (1 << 29):
            x = x - (1 << 30)
        return x / self.Q16_SCALE
    
    def split_input(self, x_int: int):
        """拆分24位输入为H(高12位)和L(低12位)"""
        H = (x_int >> 15) & 0xFFF
        L = x_int & 0xFFF
        return H, L
    
    def compute_approximation(self, x_int: int) -> int:
        """使用两个查找表计算近似值"""
        H, L = self.split_input(x_int)
        A = self.table0[H]  # 基础值
        B = self.table1[H]  # 斜率
        
        base = A << 15
        inc = (B * L) >> 4  # 增量计算
        
        result = base + inc
        return result & self.MAX_24BIT
    
    def compute_float(self, x_float: float) -> float:
        """完整计算：浮点数输入 -> 浮点数输出"""
        x_int = self.float_to_q8_16(x_float)
        result_int = self.compute_approximation(x_int)
        return self.q8_16_to_float(result_int)

# ===================== 3. 查找表生成器 =====================
def generate_tables(func_name: str = "gelu"):
    """生成两个12位查找表"""
    print(f"正在生成 {func_name} 函数的查找表...")
    
    # 选择函数
    if func_name == "gelu":
        func = NonlinearFunctions.gelu
    elif func_name == "tanh":
        func = NonlinearFunctions.tanh
    elif func_name == "sigmoid":
        func = NonlinearFunctions.sigmoid
    else:
        func = NonlinearFunctions.gelu
    
    # 创建表系统
    table_system = LookupTableSystem()
    
    # 预计算所有H点的函数值和导数
    # 为简化，这里用中心差分法近似导数
    for H in range(4096):
        x0 = H / 16.0  # 实际值
        
        # 计算函数值
        f_val = func(x0)
        f_fixed = table_system.float_to_q8_16(f_val)
        
        # 计算导数近似（中心差分）
        delta = 0.001
        f_val_plus = func(x0 + delta)
        f_val_minus = func(x0 - delta)
        df_val = (f_val_plus - f_val_minus) / (2 * delta)
        df_fixed = table_system.float_to_q8_16(df_val)
        
        # 存储到查找表
        table_system.table0[H] = (f_fixed + 2048) >> 15  # 四舍五入
        table_system.table1[H] = df_fixed >> 15
    
    print(f"查找表生成完成！")
    return table_system

# ===================== 4. 误差计算核心 =====================
def calculate_mae_mse(table_system, func_name: str = "gelu", 
                     num_samples: int = 10000, 
                     input_range: tuple = (-4, 4)):
    """
    计算MAE和MSE
    
    参数:
        table_system: 查找表系统
        func_name: 函数名称
        num_samples: 样本数量
        input_range: 输入范围
    
    返回:
        (mae, mse, rmse) 元组
    """
    # 选择精确函数
    if func_name == "gelu":
        exact_func = NonlinearFunctions.gelu
    elif func_name == "tanh":
        exact_func = NonlinearFunctions.tanh
    elif func_name == "sigmoid":
        exact_func = NonlinearFunctions.sigmoid
    else:
        exact_func = NonlinearFunctions.gelu
    
    print(f"\n正在计算 {func_name} 函数的误差...")
    print(f"样本数: {num_samples}, 输入范围: {input_range}")
    
    # 生成随机测试样本
    np.random.seed(42)  # 固定随机种子，结果可重复
    test_inputs = np.random.uniform(input_range[0], input_range[1], num_samples)
    
    mae_sum = 0.0  # 累计绝对误差
    mse_sum = 0.0  # 累计平方误差
    max_abs_error = 0.0
    errors_list = []  # 存储所有误差
    
    for i, x in enumerate(test_inputs):
        # 精确值
        exact = exact_func(x)
        
        # 查找表近似值
        approx = table_system.compute_float(x)
        
        # 计算误差
        abs_error = abs(exact - approx)
        sq_error = (exact - approx) ** 2
        
        # 累加
        mae_sum += abs_error
        mse_sum += sq_error
        errors_list.append(abs_error)
        
        # 更新最大误差
        if abs_error > max_abs_error:
            max_abs_error = abs_error
        
        # 显示进度
        if (i + 1) % (num_samples // 10) == 0:
            progress = (i + 1) / num_samples * 100
            print(f"进度: {progress:.0f}%", end='\r')
    
    # 计算最终指标
    mae = mae_sum / num_samples
    mse = mse_sum / num_samples
    rmse = np.sqrt(mse)
    
    # 转换为Q8.16格式的误差
    mae_q = int(mae * table_system.Q16_SCALE)
    mse_q = int(mse * (table_system.Q16_SCALE ** 2))
    
    return {
        'mae': mae,
        'mse': mse,
        'rmse': rmse,
        'max_abs_error': max_abs_error,
        'mae_q8_16': mae_q,
        'mse_q8_16': mse_q,
        'errors': np.array(errors_list)
    }

# ===================== 5. 主测试函数 =====================
def main():
    """主测试函数"""
    print("=" * 60)
    print("两个12位查找表近似方案 - MAE和MSE计算")
    print("=" * 60)
    
    # 测试配置
    functions_to_test = ["gelu", "tanh", "sigmoid"]
    num_samples = 20000  # 可以调整样本数
    input_range = (-4, 4)  # BERT典型输入范围
    
    results = {}
    
    for func_name in functions_to_test:
        print(f"\n{'='*40}")
        print(f"测试函数: {func_name.upper()}")
        print(f"{'='*40}")
        
        # 1. 生成查找表
        start_time = time.time()
        table_system = generate_tables(func_name)
        table_gen_time = time.time() - start_time
        print(f"查找表生成时间: {table_gen_time:.3f}秒")
        
        # 2. 计算误差指标
        start_time = time.time()
        errors = calculate_mae_mse(table_system, func_name, num_samples, input_range)
        calc_time = time.time() - start_time
        
        # 3. 显示结果
        print(f"\n误差计算结果:")
        print(f"  MAE (平均绝对误差): {errors['mae']:.8f}")
        print(f"  MSE (均方误差): {errors['mse']:.10f}")
        print(f"  RMSE (均方根误差): {errors['rmse']:.8f}")
        print(f"  最大绝对误差: {errors['max_abs_error']:.8f}")
        print(f"  Q8.16格式MAE: {errors['mae_q8_16']}")
        print(f"  Q8.16格式MSE: {errors['mse_q8_16']}")
        print(f"  误差计算时间: {calc_time:.3f}秒")
        
        # 4. 误差分布统计
        errors_array = errors['errors']
        print(f"\n误差分布统计:")
        for percentile in [50, 75, 90, 95, 99]:
            value = np.percentile(errors_array, percentile)
            print(f"  {percentile}%样本误差 ≤ {value:.8f}")
        
        # 保存结果
        results[func_name] = errors
    
    # 6. 结果对比表格
    print(f"\n{'='*60}")
    print("函数性能对比总结")
    print(f"{'='*60}")
    print(f"{'函数':<10} {'MAE':<15} {'MSE':<20} {'RMSE':<15} {'Max Error':<15}")
    print(f"{'-'*75}")
    
    for func_name in functions_to_test:
        err = results[func_name]
        print(f"{func_name:<10} {err['mae']:<15.8f} {err['mse']:<20.10f} "
              f"{err['rmse']:<15.8f} {err['max_abs_error']:<15.8f}")
    
    # 7. 简单示例：测试几个特定点
    print(f"\n{'='*60}")
    print("特定点测试示例")
    print(f"{'='*60}")
    
    # 使用GELU作为示例
    gelu_tables = generate_tables("gelu")
    test_points = [-2.0, -1.0, -0.5, 0.0, 0.5, 1.0, 2.0]
    
    print(f"\n{'输入(x)':<10} {'精确值':<15} {'近似值':<15} {'绝对误差':<15} {'相对误差(%)':<15}")
    print(f"{'-'*70}")
    
    for x in test_points:
        exact = NonlinearFunctions.gelu(x)
        approx = gelu_tables.compute_float(x)
        abs_err = abs(exact - approx)
        rel_err = abs_err / (abs(exact) + 1e-10) * 100
        
        print(f"{x:<10.4f} {exact:<15.8f} {approx:<15.8f} "
              f"{abs_err:<15.8f} {rel_err:<15.2f}")

if __name__ == "__main__":
    main()