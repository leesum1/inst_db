// Application state
const app = {
    currentPage: 1,
    totalPages: 1,
    pageSize: 50,
    orderBy: 'sequence_id',
    orderDir: 'asc',
    searchTerm: '',
    registerFilter: '',
    currentSequenceId: null,
    
    // Initialize application
    init() {
        this.setupUpload();
        this.setupEventListeners();
    },
    
    // Setup file upload
    setupUpload() {
        const uploadArea = document.getElementById('upload-area');
        const fileInput = document.getElementById('file-input');
        
        // Click to upload
        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });
        
        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.uploadFile(files[0]);
            }
        });
        
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.uploadFile(e.target.files[0]);
            }
        });
    },
    
    // Setup event listeners
    setupEventListeners() {
        // Enter key in search box
        document.getElementById('search-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.applyFilters();
            }
        });
        
        // Page size change
        document.getElementById('page-size').addEventListener('change', () => {
            this.applyFilters();
        });
        
        // Click outside modal to close
        window.addEventListener('click', (e) => {
            const detailModal = document.getElementById('detail-modal');
            const depModal = document.getElementById('dependency-modal');
            if (e.target === detailModal) {
                this.closeModal();
            }
            if (e.target === depModal) {
                this.closeDependencyModal();
            }
        });
    },
    
    // Upload file to server
    async uploadFile(file) {
        const statusDiv = document.getElementById('upload-status');
        statusDiv.className = 'upload-status';
        statusDiv.textContent = '上传中...';
        statusDiv.style.display = 'block';
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                statusDiv.className = 'upload-status success';
                statusDiv.textContent = `✓ 文件 "${data.filename}" 上传成功！`;
                
                // Show statistics
                this.displayStatistics(data.statistics);
                
                // Load registers for filter
                await this.loadRegisters();
                
                // Show controls and table sections
                document.getElementById('stats-section').style.display = 'block';
                document.getElementById('controls-section').style.display = 'block';
                document.getElementById('table-section').style.display = 'block';
                
                // Load first page of instructions
                this.loadInstructions();
            } else {
                statusDiv.className = 'upload-status error';
                statusDiv.textContent = `✗ 错误: ${data.error}`;
            }
        } catch (error) {
            statusDiv.className = 'upload-status error';
            statusDiv.textContent = `✗ 上传失败: ${error.message}`;
        }
    },
    
    // Display statistics
    displayStatistics(stats) {
        document.getElementById('stat-instructions').textContent = stats.total_instructions.toLocaleString();
        document.getElementById('stat-registers').textContent = stats.total_register_deps.toLocaleString();
        document.getElementById('stat-memory').textContent = stats.total_memory_ops.toLocaleString();
        document.getElementById('stat-unique-regs').textContent = stats.unique_registers.toLocaleString();
    },
    
    // Load registers for filter dropdown
    async loadRegisters() {
        try {
            const response = await fetch('/api/registers');
            const data = await response.json();
            
            const select = document.getElementById('register-filter');
            select.innerHTML = '<option value="">全部寄存器</option>';
            
            data.registers.forEach(reg => {
                const option = document.createElement('option');
                option.value = reg;
                option.textContent = reg;
                select.appendChild(option);
            });
        } catch (error) {
            console.error('Failed to load registers:', error);
        }
    },
    
    // Load instructions with current filters
    async loadInstructions() {
        const tableBody = document.getElementById('table-body');
        tableBody.innerHTML = '<tr><td colspan="4" class="loading">加载中...</td></tr>';
        
        const params = new URLSearchParams({
            page: this.currentPage,
            page_size: this.pageSize,
            order_by: this.orderBy,
            order_dir: this.orderDir,
        });
        
        if (this.searchTerm) {
            params.append('search', this.searchTerm);
        }
        
        if (this.registerFilter) {
            params.append('register', this.registerFilter);
        }
        
        try {
            const response = await fetch(`/api/instructions?${params}`);
            const data = await response.json();
            
            if (response.ok) {
                this.displayInstructions(data.instructions);
                this.updatePagination(data.page, data.total_pages, data.total);
            } else {
                tableBody.innerHTML = `<tr><td colspan="4" class="error">错误: ${data.error}</td></tr>`;
            }
        } catch (error) {
            tableBody.innerHTML = `<tr><td colspan="4" class="error">加载失败: ${error.message}</td></tr>`;
        }
    },
    
    // Display instructions in table
    displayInstructions(instructions) {
        const tableBody = document.getElementById('table-body');
        
        if (instructions.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="loading">没有找到匹配的指令</td></tr>';
            return;
        }
        
        tableBody.innerHTML = instructions.map(inst => `
            <tr>
                <td>${inst.sequence_id}</td>
                <td><code>${inst.pc}</code></td>
                <td><code>${inst.disassembly}</code></td>
                <td>
                    <button class="btn btn-action btn-info" onclick="app.showDetail(${inst.sequence_id})">详情</button>
                    <button class="btn btn-action btn-link" onclick="app.showDependencies(${inst.sequence_id})">依赖链</button>
                </td>
            </tr>
        `).join('');
    },
    
    // Update pagination controls
    updatePagination(page, totalPages, totalItems) {
        this.currentPage = page;
        this.totalPages = totalPages;
        
        document.getElementById('page-info').textContent = `第 ${page} / ${totalPages} 页 (共 ${totalItems} 条)`;
        
        document.getElementById('btn-first').disabled = page === 1;
        document.getElementById('btn-prev').disabled = page === 1;
        document.getElementById('btn-next').disabled = page >= totalPages;
        document.getElementById('btn-last').disabled = page >= totalPages;
    },
    
    // Apply filters
    applyFilters() {
        this.searchTerm = document.getElementById('search-input').value.trim();
        this.registerFilter = document.getElementById('register-filter').value;
        this.pageSize = parseInt(document.getElementById('page-size').value);
        this.currentPage = 1;
        this.loadInstructions();
    },
    
    // Reset filters
    resetFilters() {
        document.getElementById('search-input').value = '';
        document.getElementById('register-filter').value = '';
        document.getElementById('page-size').value = '50';
        this.searchTerm = '';
        this.registerFilter = '';
        this.pageSize = 50;
        this.currentPage = 1;
        this.loadInstructions();
    },
    
    // Sort by column
    sortBy(column) {
        if (this.orderBy === column) {
            this.orderDir = this.orderDir === 'asc' ? 'desc' : 'asc';
        } else {
            this.orderBy = column;
            this.orderDir = 'asc';
        }
        this.loadInstructions();
    },
    
    // Pagination controls
    goToPage(page) {
        if (page === -1) {
            this.currentPage = this.totalPages;
        } else {
            this.currentPage = page;
        }
        this.loadInstructions();
    },
    
    nextPage() {
        if (this.currentPage < this.totalPages) {
            this.currentPage++;
            this.loadInstructions();
        }
    },
    
    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            this.loadInstructions();
        }
    },
    
    // Show instruction detail modal
    async showDetail(sequenceId) {
        const modal = document.getElementById('detail-modal');
        const modalBody = document.getElementById('modal-body');
        const modalTitle = document.getElementById('modal-title');
        
        modalTitle.textContent = `指令详情 - Sequence ID: ${sequenceId}`;
        modalBody.innerHTML = '<div class="loading">加载中...</div>';
        modal.style.display = 'block';
        
        try {
            const response = await fetch(`/api/instruction/${sequenceId}`);
            const data = await response.json();
            
            if (response.ok) {
                modalBody.innerHTML = this.formatInstructionDetail(data);
            } else {
                modalBody.innerHTML = `<div class="error">错误: ${data.error}</div>`;
            }
        } catch (error) {
            modalBody.innerHTML = `<div class="error">加载失败: ${error.message}</div>`;
        }
    },
    
    // Format instruction detail HTML
    formatInstructionDetail(data) {
        const inst = data.instruction;
        let html = '<div class="detail-section">';
        html += '<h3>基本信息</h3>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-label">Sequence ID:</div><div class="detail-value">${inst.sequence_id}</div>`;
        html += `<div class="detail-label">PC:</div><div class="detail-value">${inst.pc}</div>`;
        html += `<div class="detail-label">反汇编:</div><div class="detail-value">${inst.disassembly}</div>`;
        if (inst.instruction_code) {
            html += `<div class="detail-label">指令码:</div><div class="detail-value">${inst.instruction_code}</div>`;
        }
        html += '</div></div>';
        
        // Register dependencies
        if (data.register_dependencies.length > 0) {
            html += '<div class="detail-section">';
            html += '<h3>寄存器依赖</h3>';
            html += '<ul class="reg-dep-list">';
            data.register_dependencies.forEach(rd => {
                const badges = [];
                if (rd.is_src) badges.push('<span class="reg-badge src">SRC</span>');
                if (rd.is_dst) badges.push('<span class="reg-badge dst">DST</span>');
                html += `<li class="reg-dep-item"><strong>${rd.register_name}</strong> ${badges.join(' ')}</li>`;
            });
            html += '</ul></div>';
        }
        
        // Memory operations
        if (data.memory_operations.length > 0) {
            html += '<div class="detail-section">';
            html += '<h3>内存操作</h3>';
            html += '<ul class="mem-op-list">';
            data.memory_operations.forEach(mo => {
                html += `<li class="mem-op-item">`;
                html += `<strong>${mo.operation_type}</strong><br>`;
                html += `虚拟地址: ${mo.virtual_address || 'N/A'}<br>`;
                html += `物理地址: ${mo.physical_address || 'N/A'}<br>`;
                html += `数据长度: ${mo.data_length} bytes`;
                html += `</li>`;
            });
            html += '</ul></div>';
        }
        
        return html;
    },
    
    // Close detail modal
    closeModal() {
        document.getElementById('detail-modal').style.display = 'none';
    },
    
    // Show dependency tree modal
    async showDependencies(sequenceId) {
        this.currentSequenceId = sequenceId;
        const modal = document.getElementById('dependency-modal');
        const depTitle = document.getElementById('dependency-title');
        
        depTitle.textContent = `源寄存器依赖链 - Sequence ID: ${sequenceId}`;
        modal.style.display = 'block';
        
        await this.loadDependencies();
    },
    
    // Load dependency tree
    async loadDependencies() {
        const depBody = document.getElementById('dependency-body');
        const maxDepth = document.getElementById('max-depth').value;
        const isTextFormat = document.getElementById('text-format').checked;
        
        depBody.innerHTML = '<div class="loading">加载中...</div>';
        
        const params = new URLSearchParams({
            max_depth: maxDepth,
            format: isTextFormat ? 'text' : 'json'
        });
        
        try {
            const response = await fetch(`/api/instruction/${this.currentSequenceId}/dependencies?${params}`);
            const data = await response.json();
            
            if (response.ok) {
                if (isTextFormat) {
                    depBody.innerHTML = `<div class="dependency-text">${data.tree}</div>`;
                } else {
                    depBody.innerHTML = this.formatDependencyTree(data.root);
                }
            } else {
                depBody.innerHTML = `<div class="error">错误: ${data.error}</div>`;
            }
        } catch (error) {
            depBody.innerHTML = `<div class="error">加载失败: ${error.message}</div>`;
        }
    },
    
    // Format dependency tree as HTML
    formatDependencyTree(node, isRoot = true) {
        let html = '';
        
        const labelClass = isRoot ? 'tree-node-label root' : 
                          node.is_cycle ? 'tree-node-label cycle' : 'tree-node-label';
        
        html += `<div class="${isRoot ? '' : 'tree-node'}">`;
        html += `<div class="${labelClass}">${node.label}</div>`;
        
        if (node.children && node.children.length > 0) {
            node.children.forEach(child => {
                html += this.formatDependencyTree(child, false);
            });
        }
        
        html += '</div>';
        
        return html;
    },
    
    // Reload dependencies with new settings
    reloadDependencies() {
        this.loadDependencies();
    },
    
    // Toggle dependency format
    toggleDependencyFormat() {
        this.loadDependencies();
    },
    
    // Close dependency modal
    closeDependencyModal() {
        document.getElementById('dependency-modal').style.display = 'none';
    },
    
    // Export data
    exportData(format) {
        const params = new URLSearchParams({
            format: format
        });
        
        if (this.searchTerm) {
            params.append('search', this.searchTerm);
        }
        
        if (this.registerFilter) {
            params.append('register', this.registerFilter);
        }
        
        window.open(`/api/export?${params}`, '_blank');
    }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    app.init();
});
