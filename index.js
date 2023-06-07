const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config()

const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)

const port = process.env.PORT || 5000;


// middleware
app.use(cors());
app.use(express.json())

const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if(!authorization){
    return res.status(401).send({error: true, message: 'unauthorized access'});
  }

  // bearer token 
  const token = authorization.split(' ')[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if(err){
      return res.status(401).send({error: true, message: 'unauthorized access'})
    }
    req.decoded = decoded;
    next();
  })

}



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.u4rhioo.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
 
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const menuCollection = client.db("bistroDb").collection("menu");
    const usersCollection = client.db("bistroDb").collection("users");
    const reviewCollection = client.db("bistroDb").collection("reviews");
    const cartCollection = client.db("bistroDb").collection("carts");

    // Token 
    app.post('/jwt', (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })

      res.send({ token })
    })


    // warning : use verifyJWT before using verifyAdmin 
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query  = { email: email}
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'admin' ){
        return res.status(403).send({error: true, message: 'forbidden message'})
      }
      next()
    }


    /**
     * do not show secure links to those who should not see the links
     * 1. use jwt token: verifyJWT
     * 3. use verifyAdmin middleWare
     */

    // users related apis 

    app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.post('/users', async(req, res) => {
      const user = req.body;
      // console.log(user)
      const query = {email: user.email}
      const existingUser = await usersCollection.findOne(query);
      // console.log( 'existingUserrrr', existingUser)
      if(existingUser){
        return res.send({message: 'user already exists'})
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    
    app.delete('/users/admin/:id', async(req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    } );

    // security layer: verifyJWT 
    app.get('/users/admin/:email', verifyJWT, async(req, res) => {
      const email = req.params.email;

      // security layer: email same 
      if(req.decoded.email !== email){
        res.send({ admin: false })
      }

      // security layer: check admin 
      const query = { email: email}
      const user = await usersCollection.findOne(query);
      const result = {admin: user?.role === 'admin'}
      res.send(result);
    })

    app.patch('/users/admin/:id', async (req, res) => {
      const id = req.params.id;
      const filter = {_id: new ObjectId(id)}
      const updateDoc = {
        $set: {
          role: 'admin'
        },
      };

      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    })
  
    // menu related apis 
    app.get('/menu',  async(req, res) => {
      const result = await menuCollection.find().toArray();
      res.send(result);
    })

    app.post('/menu', verifyJWT, verifyAdmin,  async(req, res) => {
      const newItem = req.body;
      const result = await menuCollection.insertOne(newItem)
      res.send(result);
    })

    app.delete('/menu/:id', verifyJWT, verifyAdmin, async(req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)}
      const result = await menuCollection.deleteOne(query);
      res.send(result);
    })

    // review related api 
    app.get('/reviews', async(req, res) => {
      const result = await reviewCollection.find().toArray();
      res.send(result);
    })

    // cart collection api
    app.get('/carts', verifyJWT, async(req, res) => {
      const email = req.query.email;
      if(!email){
        res.send([]);
      }


      const decodedEmail = req.decoded.email;
      if(email !== decodedEmail){
        return res.status(403).send({error: true, message: 'forbidden access'})
      }

      const query = {email: email};
      const result = await cartCollection.find(query).toArray();
      res.send(result);

    });

    
    app.post('/carts', async(req, res) => {
      const item = req.body;
      // console.log(item);
      const result = await cartCollection.insertOne(item);
      res.send(result);

    })

    app.delete('/carts/:id', async(req, res) => {
      const id = req.params.id;
      const query = {_id: new ObjectId(id)};
      const result = await cartCollection.deleteOne(query);
      res.send(result);
    } )

    // create payment intent 
    app.post('/create-payment-intent', async(req, res) => {
      const {price} = req.body;
      const amount = price*100;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types: ['card']
      });
      res.send({
        clientSecret: paymentIntent.client_secret
      })
    })



    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);




app.get('/', (req, res) => {
    res.send('boss is running')
})

app.listen(port, () => {
    console.log(`bistro boss is sitting on port ${port}`);
})


/**
 * _______________________
 * Naming convention
 * _______________________
 * 
 * users: userCollection
 * app.get('/users')    (for all users)
 * app.get('/users/:id')  (FOR PARTICULAR USER)
 * app.post('/users')     (for create new user)
 * app.patch('/users/:id')   (for update particular user) or
 * app.put('/users/:id')   (for update particular user)
 * app.delete('/users/:id)  (for delete particular id )
 */