#!/usr/bin/env python3
"""
LVT Protocol Storage Analysis Visualization Tool
分析LVT协议中每个参与方的存储开销并生成可视化图表
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
import sys
from pathlib import Path

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class StorageAnalyzer:
    def __init__(self, results_dir="storage_results"):
        self.results_dir = Path(results_dir)
        self.data = []
        
    def load_data(self):
        """加载所有存储分析数据"""
        print("Loading storage analysis data...")
        
        for party_dir in self.results_dir.glob("parties_*"):
            num_parties = int(party_dir.name.split("_")[1])
            csv_file = party_dir / "storage_analysis_results.csv"
            
            if csv_file.exists():
                try:
                    df = pd.read_csv(csv_file)
                    df['num_parties'] = num_parties
                    df['party_id'] = range(1, len(df) + 1)
                    self.data.append(df)
                    print(f"Loaded data for {num_parties} parties: {len(df)} records")
                except Exception as e:
                    print(f"Error loading {csv_file}: {e}")
        
        if self.data:
            self.df = pd.concat(self.data, ignore_index=True)
            print(f"Total records loaded: {len(self.df)}")
        else:
            print("No data found!")
            return False
        return True
    
    def analyze_storage_components(self):
        """分析存储组件的分布"""
        print("\n=== Storage Components Analysis ===")
        
        # 计算各组件占总存储的比例
        components = ['lut_share_size', 'cip_lut_size', 'cr_i_size', 
                     'user_pk_size', 'global_pk_size', 'rotation_size',
                     'table_size', 'p_to_m_size', 'bsgs_size']
        
        total_by_component = self.df[components].sum()
        total_storage = total_by_component.sum()
        
        print(f"Total storage across all parties: {total_storage / 1024 / 1024:.2f} MB")
        print("\nStorage component distribution:")
        for component in components:
            percentage = (total_by_component[component] / total_storage) * 100
            size_mb = total_by_component[component] / 1024 / 1024
            print(f"  {component}: {size_mb:.2f} MB ({percentage:.1f}%)")
    
    def plot_storage_vs_parties(self):
        """绘制存储开销与参与方数量的关系"""
        plt.figure(figsize=(12, 8))
        
        # 按参与方数量分组计算平均存储
        avg_storage = self.df.groupby('num_parties')['total_memory'].mean() / 1024 / 1024
        peak_storage = self.df.groupby('num_parties')['peak_memory'].mean() / 1024 / 1024
        
        plt.subplot(2, 2, 1)
        plt.plot(avg_storage.index, avg_storage.values, 'bo-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Average Storage per Party (MB)')
        plt.title('Storage vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        plt.subplot(2, 2, 2)
        plt.plot(peak_storage.index, peak_storage.values, 'ro-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Peak Memory per Party (MB)')
        plt.title('Peak Memory vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        # 总存储开销
        plt.subplot(2, 2, 3)
        total_storage = avg_storage * avg_storage.index
        plt.plot(total_storage.index, total_storage.values, 'go-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Total Storage (MB)')
        plt.title('Total Storage vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        # 存储效率（每参与方平均存储）
        plt.subplot(2, 2, 4)
        storage_efficiency = avg_storage / avg_storage.index
        plt.plot(storage_efficiency.index, storage_efficiency.values, 'mo-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Storage per Party per Party Count (MB)')
        plt.title('Storage Efficiency vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('storage_vs_parties.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_storage_components(self):
        """绘制存储组件的详细分析"""
        plt.figure(figsize=(15, 10))
        
        components = ['lut_share_size', 'cip_lut_size', 'cr_i_size', 
                     'user_pk_size', 'global_pk_size', 'rotation_size',
                     'table_size', 'p_to_m_size', 'bsgs_size']
        
        component_names = ['LUT Shares', 'Encrypted LUT', 'Rotation Ciphertexts',
                          'User Public Keys', 'Global Public Key', 'Rotation Value',
                          'Original Table', 'P_to_m Mapping', 'BSGS Precomputation']
        
        # 按参与方数量分组的组件存储
        for i, (component, name) in enumerate(zip(components, component_names)):
            plt.subplot(3, 3, i+1)
            
            component_data = self.df.groupby('num_parties')[component].mean() / 1024 / 1024
            plt.plot(component_data.index, component_data.values, 'o-', linewidth=2, markersize=6)
            plt.xlabel('Number of Parties')
            plt.ylabel(f'{name} (MB)')
            plt.title(f'{name} vs Parties')
            plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('storage_components.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_heatmap(self):
        """绘制存储开销热力图"""
        plt.figure(figsize=(12, 8))
        
        # 创建热力图数据
        heatmap_data = self.df.pivot_table(
            values='total_memory', 
            index='num_parties', 
            columns='party_id', 
            aggfunc='mean'
        ) / 1024 / 1024  # 转换为MB
        
        sns.heatmap(heatmap_data, annot=True, fmt='.1f', cmap='YlOrRd', 
                   cbar_kws={'label': 'Storage (MB)'})
        plt.title('Storage Usage Heatmap by Party and Number of Parties')
        plt.xlabel('Party ID')
        plt.ylabel('Number of Parties')
        
        plt.tight_layout()
        plt.savefig('storage_heatmap.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_memory_growth(self):
        """绘制内存增长分析"""
        plt.figure(figsize=(12, 6))
        
        # 计算内存增长
        self.df['memory_growth'] = self.df['peak_memory'] - self.df['total_memory']
        
        plt.subplot(1, 2, 1)
        growth_by_parties = self.df.groupby('num_parties')['memory_growth'].mean() / 1024 / 1024
        plt.plot(growth_by_parties.index, growth_by_parties.values, 'co-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Memory Growth (MB)')
        plt.title('Memory Growth vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        plt.subplot(1, 2, 2)
        # 内存使用效率（总存储/峰值内存）
        efficiency = self.df.groupby('num_parties').apply(
            lambda x: (x['total_memory'].mean() / x['peak_memory'].mean()) * 100
        )
        plt.plot(efficiency.index, efficiency.values, 'ko-', linewidth=2, markersize=8)
        plt.xlabel('Number of Parties')
        plt.ylabel('Memory Efficiency (%)')
        plt.title('Memory Efficiency vs Number of Parties')
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('memory_growth.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def generate_summary_report(self):
        """生成总结报告"""
        report_file = "storage_analysis_summary.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("LVT Protocol Storage Analysis Summary Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Analysis Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Records: {len(self.df)}\n")
            f.write(f"Number of Parties Tested: {sorted(self.df['num_parties'].unique())}\n\n")
            
            # 总体统计
            f.write("Overall Statistics:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Average Storage per Party: {self.df['total_memory'].mean() / 1024 / 1024:.2f} MB\n")
            f.write(f"Peak Memory per Party: {self.df['peak_memory'].mean() / 1024 / 1024:.2f} MB\n")
            f.write(f"Total Storage (all parties): {self.df['total_memory'].sum() / 1024 / 1024:.2f} MB\n\n")
            
            # 按参与方数量的统计
            f.write("Statistics by Number of Parties:\n")
            f.write("-" * 30 + "\n")
            for num_parties in sorted(self.df['num_parties'].unique()):
                subset = self.df[self.df['num_parties'] == num_parties]
                f.write(f"\n{num_parties} Parties:\n")
                f.write(f"  Average Storage: {subset['total_memory'].mean() / 1024 / 1024:.2f} MB\n")
                f.write(f"  Peak Memory: {subset['peak_memory'].mean() / 1024 / 1024:.2f} MB\n")
                f.write(f"  Total Storage: {subset['total_memory'].sum() / 1024 / 1024:.2f} MB\n")
                f.write(f"  Storage per Party: {subset['total_memory'].mean() / 1024 / 1024 / num_parties:.2f} MB\n")
            
            # 存储组件分析
            f.write("\n\nStorage Component Analysis:\n")
            f.write("-" * 30 + "\n")
            components = ['lut_share_size', 'cip_lut_size', 'cr_i_size', 
                         'user_pk_size', 'global_pk_size', 'rotation_size',
                         'table_size', 'p_to_m_size', 'bsgs_size']
            
            for component in components:
                avg_size = self.df[component].mean() / 1024 / 1024
                percentage = (self.df[component].mean() / self.df['total_memory'].mean()) * 100
                f.write(f"{component}: {avg_size:.2f} MB ({percentage:.1f}%)\n")
        
        print(f"Summary report generated: {report_file}")
    
    def run_analysis(self):
        """运行完整的存储分析"""
        if not self.load_data():
            return
        
        print("\nRunning storage analysis...")
        
        # 分析存储组件
        self.analyze_storage_components()
        
        # 生成可视化图表
        print("\nGenerating visualizations...")
        self.plot_storage_vs_parties()
        self.plot_storage_components()
        self.plot_heatmap()
        self.plot_memory_growth()
        
        # 生成总结报告
        print("\nGenerating summary report...")
        self.generate_summary_report()
        
        print("\nStorage analysis completed!")

def main():
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    else:
        results_dir = "storage_results"
    
    analyzer = StorageAnalyzer(results_dir)
    analyzer.run_analysis()

if __name__ == "__main__":
    main() 