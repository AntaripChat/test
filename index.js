const arycore = require('aryacore');

const app = arycore(); 

app.get('/', (req, res) => {
  res.send('Hello, World! Antarip');
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});