
const testRouts = (app) => {
  app.get('/test', (req, res) => {
    res.send('This is a test route');
  });
};
module.exports = testRouts;