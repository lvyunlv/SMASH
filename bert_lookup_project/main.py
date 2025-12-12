"""
主程序入口 - 演示完整的使用流程
"""
import numpy as np
import matplotlib.pyplot as plt

print("BERT非线性函数查找表近似系统")
print("=" * 50)

# 1. 测试GELU函数
print("\n1. 测试GELU函数")
print("-" * 30)

# 生成查找表
from table_generator import TableGenerator
from error_analyzer import ErrorAnalyzer

gen = TableGenerator("gelu")
table_system = gen.generate_tables()

# 误差分析
analyzer = ErrorAnalyzer(table_system)
stats = analyzer.analyze_errors(num_samples=10000)
analyzer.print_error_report(stats)

# 测试特定点
analyzer.test_specific_points()

# 2. 测试所有函数
print("\n\n2. 测试所有函数")
print("-" * 30)

functions = ["gelu", "tanh", "sigmoid", "relu"]
results = {}

for func_name in functions:
    print(f"\n正在处理 {func_name} 函数...")
    
    # 生成查找表
    gen = TableGenerator(func_name)
    table_system = gen.generate_tables()
    
    # 误差分析
    analyzer = ErrorAnalyzer(table_system)
    stats = analyzer.analyze_errors(num_samples=5000)
    results[func_name] = stats
    
    # 显示关键结果
    print(f"  平均绝对误差: {stats['mean_abs_error']:.8f}")
    print(f"  最大绝对误差: {stats['max_abs_error']:.8f}")
    print(f"  平均相对误差: {stats['mean_rel_error']:.2%}")

# 3. 结果对比
print("\n\n3. 函数性能对比")
print("-" * 30)
print(f"{'函数':<10} {'MAE':<15} {'Max AE':<15} {'Mean RE':<15}")
print("-" * 55)

for func_name in functions:
    stats = results[func_name]
    print(f"{func_name:<10} {stats['mean_abs_error']:<15.8f} "
          f"{stats['max_abs_error']:<15.8f} {stats['mean_rel_error']:<15.2%}")

# 4. 保存查找表
print("\n\n4. 保存查找表")
print("-" * 30)

for func_name in functions[:3]:  # 保存前3个函数的表
    gen = TableGenerator(func_name)
    table_system = gen.generate_tables()
    gen.save_tables(f"{func_name}_tables.npy")
    print(f"  {func_name} 查找表已保存到 {func_name}_tables.npy")

print("\n程序执行完成！")