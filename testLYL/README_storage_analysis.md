# LVT Protocol Storage Analysis Tools

这个目录包含了用于分析LVT（Look-up Table）协议中每个参与方存储开销的完整工具集。

## 文件说明

### 1. `storage_analysis.cpp`
主要的存储分析程序，用于：
- 分析LVT对象中各个组件的存储开销
- 监控内存使用情况
- 生成详细的存储分析报告
- 支持不同参数配置的测试

### 2. `storage_test_runner.sh`
批量存储测试脚本，用于：
- 自动化运行不同参数配置的存储测试
- 支持多参与方并发测试
- 收集和整理测试结果
- 生成测试报告

### 3. `storage_visualization.py`
数据可视化和分析工具，用于：
- 加载和分析存储测试数据
- 生成各种可视化图表
- 分析存储组件的分布
- 生成详细的总结报告

## 使用方法

### 步骤1：编译存储分析程序

```bash
cd /workspace/lyl/SMASH
make storage_analysis
```

### 步骤2：运行存储分析测试

#### 单个测试
```bash
cd testLYL
# 测试2个参与方，表大小2^10，m_bits=10
./storage_test_runner.sh test 2
```

#### 批量测试
```bash
# 测试所有参与方数量（2, 4, 8, 16, 32, 64）
./storage_test_runner.sh test-all
```

#### 查看结果
```bash
# 查看测试结果摘要
./storage_test_runner.sh results

# 生成详细报告
./storage_test_runner.sh report
```

### 步骤3：数据可视化

```bash
# 安装Python依赖
pip3 install pandas matplotlib seaborn numpy

# 运行可视化分析
python3 storage_visualization.py
```

## 存储组件分析

LVT协议中的主要存储组件包括：

### 1. LUT Shares (`lut_share_size`)
- **描述**: 每个参与方持有的查找表份额
- **大小**: 与表大小成正比 (2^table_size_bits)
- **用途**: 存储加密后的表项份额

### 2. Encrypted LUT (`cip_lut_size`)
- **描述**: 加密的查找表数据
- **大小**: 与参与方数量和表大小成正比
- **用途**: 存储同态加密的表项

### 3. Rotation Ciphertexts (`cr_i_size`)
- **描述**: 旋转操作的密文
- **大小**: 与参与方数量成正比
- **用途**: 实现表的随机旋转

### 4. Public Keys (`user_pk_size`, `global_pk_size`)
- **描述**: 用户公钥和全局公钥
- **大小**: 固定大小，与参与方数量相关
- **用途**: 加密和密钥管理

### 5. Original Table (`table_size`)
- **描述**: 原始查找表数据
- **大小**: 与表大小成正比
- **用途**: 存储明文表项

### 6. P_to_m Mapping (`p_to_m_size`)
- **描述**: 点到消息的映射表
- **大小**: 与m_bits相关
- **用途**: 离散对数计算优化

### 7. BSGS Precomputation (`bsgs_size`)
- **描述**: Baby-Step Giant-Step预计算表
- **大小**: 固定大小 (2^32)
- **用途**: 离散对数计算加速

## 测试参数配置

### 参与方数量 (PARTY_COUNTS)
- 测试范围: 2, 4, 8, 16, 32, 64
- 影响: 存储开销随参与方数量线性增长

### 表大小 (TABLE_SIZE_BITS)
- 测试范围: 8, 10, 12, 14, 16
- 影响: 存储开销随表大小指数增长

### M位数 (M_BITS)
- 测试范围: 8, 10, 12, 14, 16
- 影响: 影响P_to_m映射和计算精度

## 输出文件

### 测试结果
- `storage_results/parties_X/`: 每个参与方数量的测试结果
- `storage_results/parties_X/storage_summary.txt`: 测试摘要
- `storage_results/parties_X/storage_analysis_results.csv`: 详细数据

### 可视化图表
- `storage_vs_parties.png`: 存储与参与方数量的关系
- `storage_components.png`: 存储组件详细分析
- `storage_heatmap.png`: 存储使用热力图
- `memory_growth.png`: 内存增长分析

### 报告文件
- `storage_analysis_summary.txt`: 综合分析报告
- `storage_analysis_report.txt`: 详细测试报告

## 性能分析

### 存储开销趋势
1. **线性增长**: 存储开销随参与方数量线性增长
2. **指数增长**: 存储开销随表大小指数增长
3. **组件分布**: 加密LUT通常占用最大存储空间

### 优化建议
1. **表大小优化**: 根据实际需求选择合适的表大小
2. **参与方数量**: 权衡安全性和存储开销
3. **缓存策略**: 利用预计算和缓存减少重复计算

## 故障排除

### 常见问题

1. **编译错误**
   ```bash
   # 确保依赖库已安装
   cd /workspace/lyl/SMASH
   make clean && make
   ```

2. **内存不足**
   ```bash
   # 减少测试参数
   # 修改storage_test_runner.sh中的参数范围
   ```

3. **网络连接问题**
   ```bash
   # 检查端口占用
   netstat -tulpn | grep :9000
   # 修改BASE_PORT变量
   ```

### 调试模式
```bash
# 启用详细日志
export DEBUG=1
./storage_test_runner.sh test 2
```

## 扩展功能

### 自定义测试
1. 修改`storage_test_runner.sh`中的参数配置
2. 添加新的存储组件分析
3. 自定义可视化图表

### 性能监控
1. 添加CPU使用率监控
2. 网络通信开销分析
3. 实时性能指标收集

## 参考文献

1. LVT Protocol Paper
2. Multi-party Computation Storage Analysis
3. Homomorphic Encryption Memory Usage
4. BSGS Algorithm Optimization

## 联系方式

如有问题或建议，请联系开发团队。 