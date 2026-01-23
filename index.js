const arycore = require('aryacore');
const testRouts = require('./routes/test.route');

const app = arycore(); 

app.get('/', (req, res) => {
  res.send('Hello, World! Antarip');
});
testRouts(app);


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});