项目完善包（不含软著/论文）：

1. 链路故障切换（failover）：topo 新增故障场景（链路 down + 转发表热切 P1）；控制器按场景热重建候选集/期望表；dashboard 新增「故障切换」场景按钮；e2e 新增 R6 断言（切换后全通过零误报）。

2. 多故障定位：controller 新增 localize_all() 返回全部取证不匹配跳；e2e 新增 R7 双故障轮（标签错配+s3 改头，断言嫌疑集 {s1,s3}）；dashboard 新增「多重故障」按钮并支持多节点标红。

3. 正式图纸：docs/figures/ 新增系统架构图.svg、算法流程图.svg（申报书点名成果，替换 ASCII 图）。

4. 收尾：单测扩展（localize_all/failover）→ VM 全量构建+测试+e2e 实测 → 浏览器验证新场景 → PROJECT.md/README/算法报告同步 → git 提交。