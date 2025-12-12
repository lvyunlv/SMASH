"""
误差分析工具 - 评估查找表近似的精度
"""
import numpy as np
import matplotlib.pyplot as plt
from nonlinear_functions import NonlinearFunctions
from lookup_table_system import LookupTableSystem
from config import INPUT_RANGE, NUM_SAMPLES, TEST_POINTS

class ErrorAnalyzer:
    def __init__(self, table_system: LookupTableSystem):
        """
        初始化误差分析器
        
        参数:
            table_system: 已配置的查找表系统
        """
        self.table_system = table_system
        self.func_name = table_system.func_name
        
    def compute_single_error(self, x_float: float):
        """
        计算单个输入的误差
        
        参数:
            x_float: 浮点数输入
        
        返回:
            (精确值, 近似值, 绝对误差, 相对误差)
        """
        # 获取精确值
        func = NonlinearFunctions.get_function(self.func_name)
        exact_float = func(x_float)
        
        # 计算近似值
        approx_float = self.table_system.compute_float(x_float)
        
        # 计算误差
        abs_error = abs(exact_float - approx_float)
        rel_error = abs_error / (abs(exact_float) + 1e-10)  # 避免除以0
        
        return exact_float, approx_float, abs_error, rel_error
    
    def analyze_errors(self, num_samples: int = NUM_SAMPLES, 
                      input_range: tuple = INPUT_RANGE):
        """
        统计分析误差
        
        参数:
            num_samples: 样本数量
            input_range: 输入范围
        
        返回:
            包含各种误差统计的字典
        """
        func = NonlinearFunctions.get_function(self.func_name)
        
        # 生成随机测试数据
        np.random.seed(42)  # 固定随机种子，使结果可重复
        test_inputs = np.random.uniform(input_range[0], input_range[1], num_samples)
        
        abs_errors = []
        rel_errors = []
        
        print(f"正在分析 {num_samples} 个样本的误差...")
        
        for i, x in enumerate(test_inputs):
            # 计算误差
            exact = func(x)
            approx = self.table_system.compute_float(x)
            
            abs_error = abs(exact - approx)
            abs_errors.append(abs_error)
            
            if abs(exact) > 1e-10:  # 避免除以很小的数
                rel_error = abs_error / abs(exact)
                rel_errors.append(rel_error)
            
            # 显示进度
            if (i + 1) % (num_samples // 10) == 0:
                progress = (i + 1) / num_samples * 100
                print(f"进度: {progress:.0f}%", end='\r')
        
        print("误差分析完成！")
        
        # 计算统计量
        stats = {
            'max_abs_error': np.max(abs_errors),
            'mean_abs_error': np.mean(abs_errors),
            'std_abs_error': np.std(abs_errors),
            'median_abs_error': np.median(abs_errors),
            'max_rel_error': np.max(rel_errors) if rel_errors else 0,
            'mean_rel_error': np.mean(rel_errors) if rel_errors else 0,
            'abs_errors': np.array(abs_errors),
            'rel_errors': np.array(rel_errors)
        }
        
        # 转换为Q8.16格式的误差
        stats['mean_abs_error_q'] = int(stats['mean_abs_error'] * (1 << 16))
        stats['max_abs_error_q'] = int(stats['max_abs_error'] * (1 << 16))
        
        return stats
    
    def print_error_report(self, stats: dict):
        """
        打印误差报告
        
        参数:
            stats: 误差统计字典
        """
        print("\n" + "="*60)
        print(f"{self.func_name.upper()} 函数误差分析报告")
        print("="*60)
        
        print("\n【绝对误差统计】")
        print(f"  最大绝对误差: {stats['max_abs_error']:.8f}")
        print(f"  平均绝对误差: {stats['mean_abs_error']:.8f}")
        print(f"  绝对误差标准差: {stats['std_abs_error']:.8f}")
        print(f"  绝对误差中位数: {stats['median_abs_error']:.8f}")
        
        print(f"\n  Q8.16格式中的平均误差: {stats['mean_abs_error_q']}")
        print(f"  Q8.16格式中的最大误差: {stats['max_abs_error_q']}")
        
        if len(stats['rel_errors']) > 0:
            print("\n【相对误差统计】")
            print(f"  最大相对误差: {stats['max_rel_error']:.4%}")
            print(f"  平均相对误差: {stats['mean_rel_error']:.4%}")
        
        print("\n【百分位数分析】")
        for p in [50, 75, 90, 95, 99]:
            percentile = np.percentile(stats['abs_errors'], p)
            print(f"  {p}%的样本误差 ≤ {percentile:.8f}")
    
    def plot_error_distribution(self, stats: dict, save_path: str = None):
        """
        绘制误差分布图
        
        参数:
            stats: 误差统计字典
            save_path: 保存路径（可选）
        """
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        # 1. 绝对误差直方图
        axes[0, 0].hist(stats['abs_errors'], bins=50, alpha=0.7, color='blue', edgecolor='black')
        axes[0, 0].set_xlabel('绝对误差')
        axes[0, 0].set_ylabel('频数')
        axes[0, 0].set_title('绝对误差分布')
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. 相对误差直方图
        if len(stats['rel_errors']) > 0:
            axes[0, 1].hist(stats['rel_errors'], bins=50, alpha=0.7, color='red', edgecolor='black')
            axes[0, 1].set_xlabel('相对误差')
            axes[0, 1].set_ylabel('频数')
            axes[0, 1].set_title('相对误差分布')
            axes[0, 1].grid(True, alpha=0.3)
        
        # 3. 误差与输入值的关系
        x_values = np.linspace(INPUT_RANGE[0], INPUT_RANGE[1], 1000)
        errors_vs_x = []
        
        func = NonlinearFunctions.get_function(self.func_name)
        for x in x_values:
            exact = func(x)
            approx = self.table_system.compute_float(x)
            errors_vs_x.append(abs(exact - approx))
        
        axes[1, 0].plot(x_values, errors_vs_x, 'g-', linewidth=1.5, alpha=0.7)
        axes[1, 0].set_xlabel('输入值 x')
        axes[1, 0].set_ylabel('绝对误差')
        axes[1, 0].set_title('误差随输入变化')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 4. 统计信息
        stats_text = (
            f"函数: {self.func_name}\n"
            f"样本数: {len(stats['abs_errors'])}\n"
            f"MAE: {stats['mean_abs_error']:.6f}\n"
            f"Max AE: {stats['max_abs_error']:.6f}\n"
            f"Std AE: {stats['std_abs_error']:.6f}\n"
            f"Max RE: {stats['max_rel_error']:.2%}\n"
            f"Mean RE: {stats['mean_rel_error']:.2%}"
        )
        
        axes[1, 1].text(0.1, 0.5, stats_text, fontsize=10,
                       verticalalignment='center',
                       bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        axes[1, 1].axis('off')
        
        plt.suptitle(f'{self.func_name.upper()}函数 - 查找表近似误差分析', fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"图表已保存到 {save_path}")
        
        plt.show()
    
    def test_specific_points(self, test_points: list = None):
        """
        测试特定点的误差
        
        参数:
            test_points: 要测试的点列表
        """
        if test_points is None:
            test_points = TEST_POINTS
        
        print(f"\n测试特定点的误差:")
        print("-" * 70)
        print(f"{'输入(x)':<10} {'精确值':<15} {'近似值':<15} {'绝对误差':<15} {'相对误差':<15}")
        print("-" * 70)
        
        for x in test_points:
            exact, approx, abs_err, rel_err = self.compute_single_error(x)
            print(f"{x:<10.4f} {exact:<15.8f} {approx:<15.8f} "
                  f"{abs_err:<15.8f} {rel_err:<15.2%}")