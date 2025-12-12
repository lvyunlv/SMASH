"""
示例运行脚本 - 演示各种使用场景
"""
import numpy as np
import math

print("BERT查找表示例")
print("=" * 50)

# 示例1：基本使用
print("\n示例1：基本使用 - GELU函数")
print("-" * 40)

from table_generator import TableGenerator
from error_analyzer import ErrorAnalyzer

# 创建GELU查找表
gen = TableGenerator("gelu")
gelu_tables = gen.generate_tables()

# 测试几个值
test_values = [0.0, 0.5, 1.0, 2.0, -1.0]
print(f"{'输入':<8} {'精确值':<15} {'查表结果':<15} {'误差':<10}")
print("-" * 50)

for x in test_values:
    exact = 0.5 * x * (1 + math.erf(x / np.sqrt(2)))  # 精确计算
    approx = gelu_tables.compute_float(x)  # 查表计算
    error = abs(exact - approx)
    print(f"{x:<8.2f} {exact:<15.8f} {approx:<15.8f} {error:<10.8f}")

# 示例2：误差分析
print("\n\n示例2：误差分析")
print("-" * 40)

analyzer = ErrorAnalyzer(gelu_tables)
stats = analyzer.analyze_errors(num_samples=5000)
analyzer.print_error_report(stats)

# 示例3：批量计算
print("\n\n示例3：批量计算")
print("-" * 40)

# 生成一批输入数据
batch_input = np.random.uniform(-2, 2, 10)
print(f"批量输入: {batch_input}")

# 批量计算
batch_output = [gelu_tables.compute_float(x) for x in batch_input]
print(f"批量输出: {batch_output}")

# 示例4：比较不同函数
print("\n\n示例4：比较不同函数在 x=1.0 处的表现")
print("-" * 40)

functions = ["gelu", "tanh", "sigmoid"]
x = 1.0

print(f"{'函数':<10} {'精确值':<15} {'查表值':<15} {'误差':<10}")
print("-" * 50)

for func_name in functions:
    gen = TableGenerator(func_name)
    tables = gen.generate_tables()
    
    # 这里需要实际的函数计算，简化演示
    if func_name == "gelu":
        exact = 0.5 * x * (1 + math.erf(x / np.sqrt(2)))
    elif func_name == "tanh":
        exact = np.tanh(x)
    elif func_name == "sigmoid":
        exact = 1.0 / (1.0 + np.exp(-x))
    
    approx = tables.compute_float(x)
    error = abs(exact - approx)
    
    print(f"{func_name:<10} {exact:<15.8f} {approx:<15.8f} {error:<10.8f}")

print("\n所有示例运行完成！")