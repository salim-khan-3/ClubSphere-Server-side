require("dotenv").config();
const Stripe = require("stripe");
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // store secret in env

// ClubSphereDBUser
// 6j9L7FTbxlTfzF5m
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.qr2egdp.mongodb.net/?appName=Cluster0`;

app.get("/", (req, res) => {
  res.send("simple crud server is running....");
});

// ===============================
// Token verification middleware
// ===============================
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const idToken = authHeader.split("Bearer ")[1].trim();

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // এখানে uid, email ইত্যাদি পাবে
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("ClubSphereDBUser");
    const userCollection = db.collection("users");
    const clubCollection = db.collection("clubs");
    const membershipCollection = db.collection("memberships");
    const eventCollection = db.collection("events");
    const eventRegistrationCollection = db.collection("eventRegistrations");
    const paymentCollection = db.collection("payments");

    // =====================
    // Role-check middleware
    // =====================
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email)
          return res.status(401).json({ message: "No email in token" });

        const user = await userCollection.findOne({ email });
        if (!user || user.role !== "admin") {
          return res
            .status(403)
            .json({ message: "Forbidden: Admin access required" });
        }
        next();
      } catch (err) {
        res.status(500).json({ message: "Server error" });
      }
    };

    // ==========================
    // user collection api
    // ==========================
    app.post("/users", async (req, res) => {
      const user = req.body;
      try {
        const existingUser = await userCollection.findOne({
          email: user.email,
        });

        if (!existingUser) {
          const newUser = {
            ...user,
            role: "member",
            createdAt: new Date(),
          };

          const result = await userCollection.insertOne(newUser);
          return res.send(result);
        }

        res.send({ message: "User already exists", user: existingUser });
      } catch (err) {
        res.status(500).send({ error: err.message });
      }
    });

    // All users fetch (Admin only)
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        res.send(users);
      } catch (err) {
        res.status(500).send({ message: "Error fetching users" });
      }
    });

    // Change user role (Admin only)
    app.patch(
      "/users/role/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email.toLowerCase();
        const { role } = req.body;
        const allowedRoles = ["admin", "clubManager", "member"];

        if (!allowedRoles.includes(role)) {
          return res.status(400).send({ message: "Invalid role" });
        }

        // Prevent admin from demoting themselves
        if (req.user?.email === email && role !== "admin") {
          return res
            .status(403)
            .send({ message: "Admin cannot change their own role" });
        }

        try {
          const result = await userCollection.updateOne(
            { email },
            { $set: { role, updatedAt: new Date() } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "User not found" });
          }

          if (result.modifiedCount === 0) {
            return res.send({ message: "Role already assigned" });
          }
          res.send({ success: true, message: `Role updated to ${role}` });
        } catch (err) {
          console.error("Error updating role:", err);
          res
            .status(500)
            .send({ message: "Error updating role", error: err.message });
        }
      }
    );

    // ==========================
    // club collection api
    // ==========================

    app.post("/clubs", async (req, res) => {
      try {
        const clubData = req.body;
        if (
          !clubData.clubName ||
          !clubData.description ||
          !clubData.managerEmail
        )
          return res.status(400).send({ message: "Missing required fields" });

        // Check if club with same name exists
        const existingClub = await clubCollection.findOne({
          clubName: clubData.clubName,
        });
        if (existingClub) {
          return res
            .status(400)
            .send({ message: "Club with this name already exists" });
        }

        const newClub = {
          ...clubData,
          membershipFee: Number(clubData.membershipFee) || 0,
          status: "pending",
          members: [],
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const result = await clubCollection.insertOne(newClub);
        res.status(201).send({
          message: "Club created successfully",
          clubId: result.insertedId,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/clubs/my-clubs", async (req, res) => {
      try {
        const managerEmail = req.query.email;

        if (!managerEmail) {
          return res.status(400).send({ message: "Manager email is required" });
        }

        const myClubs = await clubCollection
          .find({ managerEmail: managerEmail })
          .toArray();

        console.log("Fetched clubs:", myClubs);

        res.send(myClubs);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching manager clubs" });
      }
    });

    app.get("/clubs/all", async (req, res) => {
      try {
        const clubs = await clubCollection.find().toArray();
        console.log("Fetched clubs:", clubs);
        res.send(clubs);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching all clubs" });
      }
    });

    app.get("/clubs/:id", async (req, res) => {
      const { id } = req.params;

      // ID validation
      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const club = await clubCollection.findOne({ _id: new ObjectId(id) });

        if (!club) {
          return res.status(404).json({ message: "Club not found" });
        }

        res.json(club);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });
    app.patch("/clubs/approve/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const result = await clubCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "approved", updatedAt: new Date() } }
        );

        res.send({ message: "Club approved", result });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error approving club" });
      }
    });

    app.patch("/clubs/reject/:id", async (req, res) => {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid ID format" });
      }

      try {
        const result = await clubCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "rejected", updatedAt: new Date() } }
        );

        res.send({ message: "Club rejected", result });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error rejecting club" });
      }
    });
    // ==========================
    // secure route
    // ==========================
    // app.patch(
    //   "/users/make-admin/:email",
    //   verifyToken,
    //   verifyAdmin,
    //   async (req, res) => {
    //     const email = req.params.email;
    //     const result = await userCollection.updateOne(
    //       { email },
    //       { $set: { role: "admin" } }
    //     );

    //     res.send({ message: "User Promoted to admin", result });
    //   }
    // );

    app.get("/admin/overview-stats", async (req, res) => {
      try {
        const totalUsers = await userCollection.countDocuments();
        const totalClubs = await clubCollection.countDocuments(); // total clubs count
        console.log(totalClubs, totalUsers);

        res.send({ totalUsers, totalClubs });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch overview stats" });
      }
    });

    // ==============================
    // eventCollection collection api
    // ==============================
    // Get all events

    const verifyClubManager = async (req, res, next) => {
      try {
        const email = req.user?.email;
        if (!email) {
          return res.status(401).send({ message: "Unauthorized" });
        }

        const user = await userCollection.findOne({ email });

        if (!user || user.role !== "clubManager") {
          return res.status(403).send({
            message: "Forbidden: Club Manager access required",
          });
        }

        req.manager = user; // future use
        next();
      } catch (error) {
        res.status(500).send({ message: "Server error" });
      }
    };

    app.get("/users/role-info", async (req, res) => {
      try {
        const { email } = req.query;

        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }

        // find user by email
        const user = await userCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // response
        res.send({
          email: user.email,
          role: user.role,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.get("/events", async (req, res) => {
      try {
        const events = await eventCollection.find().sort({ date: 1 }).toArray();
        res.send(events);
      } catch (err) {
        res.status(500).send({ message: "Error fetching events" });
      }
    });

    // Create new event
    // server.js / index.js (Node.js)
    app.post("/events", async (req, res) => {
      try {
        const {
          title,
          description,
          date,
          location,
          isPaid,
          eventFee,
          maxAttendees,
          clubId,
          clubName,
        } = req.body;

        if (!clubId)
          return res.status(400).send({ message: "Club ID is required" });

        const newEvent = {
          title,
          description,
          date,
          location,
          isPaid,
          eventFee,
          maxAttendees,
          clubId, // save club id
          createdAt: new Date(),
          clubName,
        };

        const result = await eventCollection.insertOne(newEvent);
        res.status(201).send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to create event" });
      }
    });

    app.get("/events/:id", async (req, res) => {
      try {
        const eventId = req.params.id;

        const query = { _id: new ObjectId(eventId) };

        const event = await eventCollection.findOne(query);

        if (!event) {
          return res.status(404).send({ message: "Event not found" });
        }
        res.status(200).send(event);
      } catch (err) {
        console.error("Error fetching event by ID:", err);
        res.status(500).send({ message: "Failed to fetch event data" });
      }
    });

    // Update event
    app.patch("/events/:id", async (req, res) => {
      const { id } = req.params;
      try {
        const updatedEvent = req.body;
        const result = await eventCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedEvent }
        );
        res.send({ message: "Event updated", result });
      } catch (err) {
        res.status(500).send({ message: "Error updating event" });
      }
    });

    // Delete event
    app.delete("/events/:id", async (req, res) => {
      const { id } = req.params;
      try {
        const result = await eventCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send({ message: "Event deleted", result });
      } catch (err) {
        res.status(500).send({ message: "Error deleting event" });
      }
    });

    // ==========================
    // payments method api
    // ==========================
    // app.post("/create-payment-intent", verifyToken, async (req, res) => {
    //   try {
    //     const { amount } = req.body;

    //     const paymentIntent = await stripe.paymentIntents.create({
    //       amount: amount * 100, // dollar → cents
    //       currency: "usd",
    //       payment_method_types: ["card"],
    //     });

    //     res.send({
    //       clientSecret: paymentIntent.client_secret,
    //     });
    //   } catch (error) {
    //     res.status(500).send({ message: error.message });
    //   }
    // });


    app.post("/create-payment-intent", verifyToken, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).send({ message: "Invalid amount" });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100,
      currency: "usd",
      payment_method_types: ["card"],
    });

    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

    app.post("/payments", verifyToken, async (req, res) => {
      try {
        const payment = {
          ...req.body,
          email: req.user.email,
          createdAt: new Date(),
        };

        const result = await paymentCollection.insertOne(payment);

        // // optional: add membership
        // await membershipCollection.insertOne({
        //   clubId: new ObjectId(payment.clubId),
        //   email: req.user.email,
        //   status: "active",
        //   joinedAt: new Date(),
        // });

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Payment save failed" });
      }
    });

    app.get("/admin/payments", verifyToken, verifyAdmin, async (req, res) => {
      const payments = await paymentCollection
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      res.send(payments);
    });

    // ==========================
    // membership collection api
    // ==========================

    app.post("/join-club", verifyToken, async (req, res) => {
      try {
        const { clubId, paymentId = null, amount = 0 } = req.body;
        const email = req.user.email;

        if (!clubId) {
          return res.status(400).send({ message: "Club ID is required" });
        }

        // Already member check
        const alreadyMember = await membershipCollection.findOne({
          clubId: new ObjectId(clubId),
          userEmail: email,
          status: "active",
        });

        if (alreadyMember) {
          return res
            .status(400)
            .send({ message: "You are already a member of this club" });
        }

        // 1. Save to payments collection (full schema)
        const paymentDoc = {
          userEmail: email,
          amount: Number(amount),
          type: "membership", // fixed for club join
          clubId: new ObjectId(clubId),
          eventId: null, // membership হলে null
          stripePaymentIntentId: paymentId || null,
          status: paymentId ? "paid" : "free",
          createdAt: new Date(),
        };

        await paymentCollection.insertOne(paymentDoc);

        // 2. Save to memberships collection
        const membershipDoc = {
          userEmail: email,
          clubId: new ObjectId(clubId),
          status: "active",
          paymentId: paymentId || null,
          joinedAt: new Date(),
        };

        await membershipCollection.insertOne(membershipDoc);

        // 3. Update club's members array (members count-এর জন্য)
        await clubCollection.updateOne(
          { _id: new ObjectId(clubId) },
          {
            $addToSet: { members: email },
            $set: { updatedAt: new Date() },
          }
        );

        res.send({
          success: true,
          message: "Successfully joined the club!",
        });
      } catch (error) {
        console.error("Join club error:", error);
        res.status(500).send({ message: "Failed to join club" });
      }
    });

    // ===============================
    // eventRegistrationCollection api
    // ===============================
    // Register for an event (free or paid)
    app.post("/register-event", verifyToken, async (req, res) => {
      try {
        const { eventId, paymentId = null, amount = 0 } = req.body;
        const email = req.user.email;

        if (!eventId) {
          return res.status(400).send({ message: "Event ID is required" });
        }

        // Check if event exists
        const event = await eventCollection.findOne({
          _id: new ObjectId(eventId),
        });
        if (!event) {
          return res.status(404).send({ message: "Event not found" });
        }

        // Check if already registered
        const alreadyRegistered = await eventRegistrationCollection.findOne({
          eventId: new ObjectId(eventId),
          userEmail: email,
          status: { $in: ["registered", "cancelled"] },
        });

        if (alreadyRegistered) {
          return res
            .status(400)
            .send({ message: "You are already registered for this event" });
        }

        // 1. Save to payments collection (if paid or free)
        const paymentDoc = {
          userEmail: email,
          amount: Number(amount),
          type: "event",
          clubId: new ObjectId(event.clubId),
          eventId: new ObjectId(eventId),
          stripePaymentIntentId: paymentId || null,
          status: paymentId ? "paid" : "free",
          createdAt: new Date(),
        };

        await paymentCollection.insertOne(paymentDoc);

        // 2. Save to eventRegistrations collection
        const registrationDoc = {
          eventId: new ObjectId(eventId),
          userEmail: email,
          clubId: new ObjectId(event.clubId),
          status: "registered",
          paymentId: paymentId || null,
          registeredAt: new Date(),
        };

        await eventRegistrationCollection.insertOne(registrationDoc);

        res.send({
          success: true,
          message: "Successfully registered for the event!",
        });
      } catch (error) {
        console.error("Event registration error:", error);
        res.status(500).send({ message: "Failed to register for event" });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`simple crud server is running on port ${port}`);
});
