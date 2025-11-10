const chatBox = document.getElementById("chatBox");
const chatInput = document.getElementById("chatInput");

async function sendMessage() {
  const message = chatInput.value.trim();
  if (!message) return;

  // show user message
  chatBox.innerHTML += `<div class="mb-1"><strong>You:</strong> ${message}</div>`;
  chatInput.value = "";

  try {
    const res = await fetch("/chat", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ message })
    });
    const data = await res.json();
    chatBox.innerHTML += `<div class="mb-2 text-blue-700"><strong>NeuroSole 🤖:</strong> ${data.reply}</div>`;
    chatBox.scrollTop = chatBox.scrollHeight;
  } catch (err) {
    chatBox.innerHTML += `<div class="text-red-600">Connection error.</div>`;
  }
}
