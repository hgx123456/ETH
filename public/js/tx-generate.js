function lookup() {
    $('#loadInstallmentsTxs').addClass('active')
    $.ajax({
        type: "GET",
        url: "/api/getpublickey",
        success: function(result) {
        alert("THE ADDRESS IS:        "+result );
            //get EthAddr
            
        },
        error: function() {
  	alert('失败 ');
 	},
        complete: function() {
            $('#loadInstallmentsTxs').removeClass('active')
        }
    })
}


function SubmitTx() {
    $('#transactionSetup').addClass('active')
    $.ajax({
        type: "GET",
        url: "/api/tx/submit",
        success: function(result) {
      alert("发起交易成功        交易数据为:        "+result );
            //get 交易数据
            
        },
        error: function() {
  	alert('失败 ');
 	},
        complete: function() {
            $('#transactionSetup').removeClass('active')
        }
    })
}

function firstsign() {
    $('#transactionSetup').addClass('active')
    $.ajax({
        type: "GET",
        url: "/api/tx/firstsign",
        success: function(result) {
      alert("哈希值为:        "+result );
            //get 交易数据
            
        },
        error: function() {
  	alert('失败 ');
 	},
        complete: function() {
            $('#transactionSetup').removeClass('active')
        }
    })
}

function secondsign() {
    $('#transactionSetup').addClass('active')
    $.ajax({
        type: "GET",
        url: "/api/tx/secondsign",
        success: function(result) {
      alert("哈希值为:        "+result );
            //get 交易数据
            
        },
        error: function() {
  	alert('失败 ');
 	},
        complete: function() {
            $('#transactionSetup').removeClass('active')
        }
    })
}
 function secondsign2() {
    $('#transactionSetup').addClass('active')
    $.ajax({
        type: "GET",
        url: "/api/tx/secondsign2",
        success: function(result) {
      alert("交易序列化值        "+result );
            //get 
            
        },
        error: function() {
  	alert('失败 ');
 	},
        complete: function() {
            $('#transactionSetup').removeClass('active')
        }
    })
}
 
