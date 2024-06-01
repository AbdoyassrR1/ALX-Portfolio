const footerElement = document.createElement("template");
footerElement.innerHTML = `
<footer class="animate__animated animate__backInUp">
  <div class="copyright">
    <p>&copy; 2024 Task Management. All rights reserved.</p>
  </div>
  <div class="author"> 
    <p>Back-end by <a href="/" class="first-author">Abdelrahman</a></p>
    <p>Front-end by <a href="/" class="second-author">Esraa Fathi</a></p>
  </div>
</footer>
`;

class Footer extends HTMLElement {
  connectedCallback() {
    this.innerHTML = footerElement.innerHTML;
  }
}

customElements.define("footer-component", Footer);
