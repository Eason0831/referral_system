$(document).ready(function() {
    // 处理提现表单中的支付方式切换
    $('input[name="method_type"]').change(function() {
        const selectedMethod = $('input[name="method_type"]:checked').val();
        
        // 隐藏所有字段
        $('#alipay_fields, #wechat_fields, #emt_fields').hide();
        
        // 显示选中的支付方式字段
        $(`#${selectedMethod}_fields`).show();
    });
    
    // 提交提现申请
    $('#submitWithdraw').click(function() {
        const form = $('#withdrawForm');
        const amount = $('#withdraw_amount').val();
        const methodType = $('input[name="method_type"]:checked').val();
        let isValid = true;
        let formData = {
            amount: amount,
            method_type: methodType
        };
        
        // 验证金额
        if (!amount || parseFloat(amount) <= 0) {
            toastr.error('请输入有效的提现金额');
            isValid = false;
            return;
        }
        
        // 根据不同支付方式验证并收集表单数据
        if (methodType === 'alipay') {
            const account = $('#alipay_account').val();
            const phone = $('#alipay_phone').val();
            
            if (!account) {
                toastr.error('请输入支付宝账号');
                isValid = false;
                return;
            }
            
            formData.account = account;
            formData.phone = phone;
            
        } else if (methodType === 'wechat') {
            const id = $('#wechat_id').val();
            const phone = $('#wechat_phone').val();
            
            if (!id) {
                toastr.error('请输入微信号');
                isValid = false;
                return;
            }
            
            formData.account = id;
            formData.phone = phone;
            
        } else if (methodType === 'emt') {
            const bankName = $('#emt_bank_name').val();
            const email = $('#emt_email').val();
            const name = $('#emt_recipient_name').val();
            const phone = $('#emt_phone').val();
            
            if (!bankName) {
                toastr.error('请选择银行');
                isValid = false;
                return;
            }
            
            if (!email) {
                toastr.error('请输入EMT邮箱');
                isValid = false;
                return;
            }
            
            if (!name) {
                toastr.error('请输入收款人姓名');
                isValid = false;
                return;
            }
            
            formData.bank_name = bankName;
            formData.account = email;
            formData.account_name = name;
            formData.phone = phone;
        }
        
        if (isValid) {
            // 显示加载指示器
            $('#submitWithdraw').prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 处理中...');
            
            // 发送AJAX请求
            $.ajax({
                url: '/apply_withdraw',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(formData),
                success: function(response) {
                    if (response.success) {
                        toastr.success('提现申请已提交');
                        $('#withdrawModal').modal('hide');
                        
                        // 重新加载页面以更新数据
                        setTimeout(function() {
                            window.location.reload();
                        }, 1500);
                    } else {
                        toastr.error(response.message || '提交失败，请稍后再试');
                    }
                },
                error: function(xhr) {
                    let errorMsg = '提交失败，请稍后再试';
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        errorMsg = xhr.responseJSON.message;
                    }
                    toastr.error(errorMsg);
                },
                complete: function() {
                    // 恢复按钮状态
                    $('#submitWithdraw').prop('disabled', false).html('申请提现');
                }
            });
        }
    });
    
    // 打开模态框时重置表单
    $('#withdrawModal').on('show.bs.modal', function() {
        $('#withdrawForm')[0].reset();
        $('input[name="method_type"]:first').prop('checked', true).trigger('change');
    });
}); 