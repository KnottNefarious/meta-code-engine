async function analyzeCode() {

    const code = document.getElementById("code").value;
    const output = document.getElementById("output");

    output.textContent = "Analyzing...";

    try {

        const response = await fetch("/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();

        if (data.status !== "ok") {
            output.textContent = "Server error:\n" + JSON.stringify(data, null, 2);
            return;
        }

        if (data.issue_count === 0) {
            output.textContent = "Issues Found: 0\n\n✔ Code appears safe.";
            return;
        }

        output.textContent =
            "Issues Found: " + data.issue_count + "\n\n" +
            data.issues.join("\n\n");

    } catch (err) {
        output.textContent = "Request failed:\n" + err;
    }
}
