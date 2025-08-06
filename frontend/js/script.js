window.addEventListener('pageshow', function (event) {
    document.getElementById("key").value = "";
    document.getElementById('tx-hash').textContent = "";
});

function submit_key() {
    document.getElementById('tx-hash').textContent = "Your request is being processed. Please stand by...";
    userInput = document.getElementById('key').value;
    console.log(userInput);

    const payload = {
        userInput: userInput
    };

    fetch('/transfer', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer your-auth-token'
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        return response.json();
    })
    .then(data => {
        console.log(data);

        if(data.tx_hash && data.amount) {
            document.getElementById('tx-hash').innerHTML = `Transaction Successful! ${data.amount} BDX was sent. Reference: <a href="https://testnet.beldex.dev/tx/${data.tx_hash}" target="_blank" rel="noopener noreferrer">${data.tx_hash}</a>.`;
        } else if (data.message) {
            document.getElementById('tx-hash').innerHTML = `${data.message}. Please try again later or <a href="https://testnet.support.beldex.io" target="_blank" rel="noopener noreferrer">contact support</a>.`;
        }else if (data.address) {
            document.getElementById('tx-hash').textContent = `${data.address}`;
        }else if (data.restrict) {
            document.getElementById('tx-hash').textContent = `${data.restrict}`;
        }else if (data.error) {
            document.getElementById('tx-hash').textContent = `${data.error}`;
        } else {
            document.getElementById('tx-hash').textContent = `Unexpected Response`;
        }
    })
    .catch(error => {
        console.error('Fetch error: ', error);
        document.getElementById('tx-hash').textContent = `Fetch error: ${error}`;
    });
}