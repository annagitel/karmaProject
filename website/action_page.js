
function saveInput() {
	const name = document.getElementById("cname");
	const expmonth = document.getElementById("expmonth");
	const expyear = document.getElementById("expyear");
	const card_num = document.getElementById("ccnum");
	const cvv = document.getElementById("cvv");
	
	let data = 
	"name : " + name.value + "\n "+
	"expmonth : " + expmonth.value + "\n" + 
	"expyear : " + expyear.value + "\n" +
	"card number : " + card_num.value + "\n" +
	"cvv : " + cvv.value; 
	
        
    const textToBLOB = new Blob([data], { type: 'text/plain' });
    const sFileName = 'formData.txt';	   

    let newLink = document.createElement("a");
    newLink.download = sFileName;

    if (window.webkitURL != null) {
        newLink.href = window.webkitURL.createObjectURL(textToBLOB);
    }
    else {
        newLink.href = window.URL.createObjectURL(textToBLOB);
        newLink.style.display = "none";
        document.body.appendChild(newLink);
    }

    newLink.click(); 
}
